# tts_service.py - Piper TTS microservice for the A2A Smart Home Lab
"""
Lightweight Flask wrapper around Piper TTS.  Downloads the voice model
on first startup, then serves audio synthesis via HTTP.

Uses the piper-tts Python API directly (not subprocess) for reliable
operation inside Docker containers.

POST /synthesize  {"text": "..."}  → audio/wav
GET  /health                       → {"status": "ok", "voice": "..."}
"""

import io
import os
import re
import json
import wave
import struct
import base64
import urllib.request
import traceback

from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, jsonify, Response

app = Flask("piper-tts")

PORT = int(os.environ.get("TTS_PORT", "5200"))
VOICE = os.environ.get("PIPER_VOICE", "en_GB-alan-medium")
VOICE_OPTIONS = [v.strip() for v in os.environ.get("PIPER_VOICE_OPTIONS", "").split(",") if v.strip()]
MODEL_DIR = Path(os.environ.get("PIPER_MODEL_DIR", "/app/models"))

# HuggingFace base URL for piper-voices
_HF_BASE = "https://huggingface.co/rhasspy/piper-voices/resolve/v1.0.0"

# Mutable active voice name (can change at runtime via /switch-voice)
_active_voice = VOICE

# Lazy-loaded Piper voice instance
_piper_voice = None
_piper_error = None


def _derive_voice_path(voice_name: str) -> str:
    """Derive the HuggingFace path from a Piper voice name.

    Piper voice naming convention:
        {lang}_{region}-{speaker}-{quality}
        e.g. en_US-hfc_female-medium  →  en/en_US/hfc_female/medium
             en_GB-alan-low           →  en/en_GB/alan/low

    The HuggingFace repo structure mirrors this as:
        {lang}/{lang}_{region}/{speaker}/{quality}/{voice_name}.onnx
    """
    parts = voice_name.split("-")
    if len(parts) < 3:
        return ""

    lang_region = parts[0]          # e.g. "en_US"
    speaker = "-".join(parts[1:-1]) # e.g. "hfc_female" or "jenny_dioco"
    quality = parts[-1]             # e.g. "medium"

    lang = lang_region.split("_")[0]  # e.g. "en"
    return f"{lang}/{lang_region}/{speaker}/{quality}"


def _model_path(voice_name: str = "") -> Path:
    return MODEL_DIR / f"{voice_name or _active_voice}.onnx"


def _config_path(voice_name: str = "") -> Path:
    return MODEL_DIR / f"{voice_name or _active_voice}.onnx.json"


def _is_voice_downloaded(voice_name: str) -> bool:
    return _model_path(voice_name).exists() and _config_path(voice_name).exists()


def _download_voice(voice_name: str = ""):
    """Download the Piper ONNX model + JSON config if not already cached."""
    voice_name = voice_name or _active_voice
    model_file = _model_path(voice_name)
    config_file = _config_path(voice_name)

    if model_file.exists() and config_file.exists():
        print(f"[tts] Voice model already cached: {voice_name}")
        return True

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    voice_path = _derive_voice_path(voice_name)
    if not voice_path:
        print(f"[tts] ERROR: Cannot parse voice name '{voice_name}'. "
              f"Expected format: lang_REGION-speaker-quality (e.g. en_US-lessac-medium)")
        return False

    onnx_url = f"{_HF_BASE}/{voice_path}/{voice_name}.onnx"
    json_url = f"{_HF_BASE}/{voice_path}/{voice_name}.onnx.json"

    for url, dest in [(onnx_url, model_file), (json_url, config_file)]:
        print(f"[tts] Downloading {url} ...")
        try:
            urllib.request.urlretrieve(url, str(dest))
            print(f"[tts] Saved: {dest} ({dest.stat().st_size / 1024 / 1024:.1f} MB)")
        except Exception as e:
            print(f"[tts] ERROR downloading {url}: {e}")
            return False

    return True


def _load_piper(voice_name: str = ""):
    """Load the Piper voice model using the Python API."""
    global _piper_voice, _piper_error, _active_voice
    voice_name = voice_name or _active_voice

    model_file = _model_path(voice_name)
    config_file = _config_path(voice_name)

    if not model_file.exists():
        _piper_error = f"Model file not found: {model_file}"
        print(f"[tts] {_piper_error}")
        return False

    try:
        from piper import PiperVoice

        _piper_voice = PiperVoice.load(
            str(model_file),
            config_path=str(config_file) if config_file.exists() else None,
            use_cuda=False,
        )
        _active_voice = voice_name
        _piper_error = None
        print(f"[tts] Piper voice loaded: {voice_name}")

        # Log available methods on first load
        methods = [m for m in dir(_piper_voice)
                   if not m.startswith('_') and callable(getattr(_piper_voice, m, None))]
        print(f"[tts] PiperVoice methods: {methods}")

        return True

    except Exception as e:
        _piper_error = f"Failed to load Piper: {e}"
        print(f"[tts] {_piper_error}")
        traceback.print_exc()
        return False


# Persistent audio output directory (bind-mounted from host)
AUDIO_DIR = Path(os.environ.get("TTS_AUDIO_DIR", "/app/audio/explanations"))


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting for cleaner TTS output."""
    t = text
    t = re.sub(r'^#{1,6}\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'\*{1,3}([^*]+)\*{1,3}', r'\1', t)
    t = re.sub(r'_{1,3}([^_]+)_{1,3}', r'\1', t)
    t = re.sub(r'`([^`]+)`', r'\1', t)
    t = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', t)
    t = re.sub(r'^\s*[-*+]\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'^\s*\d+\.\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'\n{3,}', '\n\n', t)
    t = t.replace('\u2014', ' - ').replace('\u2013', ' - ')
    return t.strip()


def _synthesize(text: str, trial_details: str = "") -> bytes:
    """Synthesize text to WAV using the Piper Python API.

    Uses synthesize_wav(text, wav_file) which writes a complete WAV
    including correct headers into the provided wave file handle.

    Saves a persistent copy to audio/explanations/ with trial details.
    """
    global _piper_voice
    if _piper_voice is None:
        if not _load_piper():
            raise RuntimeError(_piper_error or "Piper voice not loaded")

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav_file:
        _piper_voice.synthesize_wav(text, wav_file)

    wav_bytes = buf.getvalue()

    if not wav_bytes or len(wav_bytes) < 44:  # 44 = minimum WAV header
        raise RuntimeError("Piper synthesize_wav produced no audio data")

    print(f"[tts] Synthesized {len(wav_bytes)} bytes via synthesize_wav")
    _save_audio_file(wav_bytes, trial_details)

    return wav_bytes


def _save_audio_file(wav_bytes: bytes, trial_details: str = ""):
    """Save a persistent copy with timestamp and trial details."""
    try:
        AUDIO_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_details = re.sub(r'[^a-zA-Z0-9_\-]', '_', trial_details or "manual")[:80]
        filename = f"{ts}_{safe_details}.wav"
        out_file = AUDIO_DIR / filename
        out_file.write_bytes(wav_bytes)
        print(f"[tts] Audio saved: {out_file}")
    except Exception as e:
        print(f"[tts] WARNING: Failed to save audio file: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _split_sentences(text: str) -> list[str]:
    """Split text into sentences for progressive synthesis.

    Uses a simple regex that splits on sentence-ending punctuation
    followed by whitespace.  Keeps each fragment non-empty.
    """
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def _synthesize_sentence_pcm(sentence: str) -> bytes:
    """Synthesize a single sentence and return raw 16-bit PCM bytes.

    Calls synthesize_wav() into a BytesIO, then strips the 44-byte
    WAV header to return only the PCM data portion.
    """
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        _piper_voice.synthesize_wav(sentence, wf)

    wav_data = buf.getvalue()
    if len(wav_data) <= 44:
        return b""

    # Read actual data offset from the WAV header
    # (standard WAV: data starts at byte 44, but be safe)
    return wav_data[44:]


def _pcm_to_wav(pcm_data: bytes, sample_rate: int = 22050) -> bytes:
    """Wrap raw 16-bit mono PCM in a WAV header."""
    channels = 1
    bits = 16
    byte_rate = sample_rate * channels * (bits // 8)
    block_align = channels * (bits // 8)
    data_size = len(pcm_data)

    header = struct.pack(
        '<4sI4s4sIHHIIHH4sI',
        b'RIFF', 36 + data_size, b'WAVE',
        b'fmt ', 16, 1, channels, sample_rate,
        byte_rate, block_align, bits,
        b'data', data_size,
    )
    return header + pcm_data


def _get_sample_rate() -> int:
    """Read sample rate from model config."""
    try:
        cfg_file = _config_path()
        if cfg_file.exists():
            with open(cfg_file) as f:
                cfg = json.load(f)
            return cfg.get("audio", {}).get("sample_rate", 22050)
    except Exception:
        pass
    return 22050


@app.route("/synthesize-progress", methods=["POST"])
def synthesize_progress():
    """Synthesize text sentence-by-sentence with SSE progress events.

    Accepts JSON {"text": "...", "trial_details": "..."}.

    Streams SSE events:
      data: {"type":"progress","percent":30,"sentence":3,"total":10}
      data: {"type":"done","audio_base64":"UklGR..."}
      data: {"type":"error","message":"..."}

    The final audio is sent as base64-encoded WAV in the done event.
    """
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    trial_details = (body.get("trial_details") or "").strip()

    if not text:
        return jsonify({"error": "No text provided"}), 400

    clean_text = _strip_markdown(text)
    if not clean_text:
        return jsonify({"error": "Text is empty after cleanup"}), 400

    global _piper_voice
    if _piper_voice is None:
        if not _load_piper():
            return jsonify({"error": _piper_error or "Piper not loaded"}), 500

    sentences = _split_sentences(clean_text)
    total = len(sentences)

    if total == 0:
        return jsonify({"error": "No sentences to synthesize"}), 400

    def generate():
        pcm_chunks = []

        for i, sentence in enumerate(sentences, 1):
            try:
                pcm = _synthesize_sentence_pcm(sentence)
                pcm_chunks.append(pcm)
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)[:200]})}\n\n"
                return

            pct = round(100 * i / total)
            yield f"data: {json.dumps({'type': 'progress', 'percent': pct, 'sentence': i, 'total': total})}\n\n"

        # Build final WAV from concatenated PCM
        all_pcm = b"".join(pcm_chunks)
        sample_rate = _get_sample_rate()
        wav_bytes = _pcm_to_wav(all_pcm, sample_rate)

        # Save persistent audio file
        _save_audio_file(wav_bytes, trial_details)

        print(f"[tts] Synthesized {len(wav_bytes)} bytes ({total} sentences) via synthesize-progress")

        audio_b64 = base64.b64encode(wav_bytes).decode("ascii")
        yield f"data: {json.dumps({'type': 'done', 'audio_base64': audio_b64})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.route("/synthesize", methods=["POST"])
def synthesize():
    """Synthesize text to speech. Accepts JSON {"text": "...", "trial_details": "..."}.
    Returns audio/wav."""
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    trial_details = (body.get("trial_details") or "").strip()

    if not text:
        return jsonify({"error": "No text provided"}), 400

    clean_text = _strip_markdown(text)

    if not clean_text:
        return jsonify({"error": "Text is empty after cleanup"}), 400

    try:
        wav_bytes = _synthesize(clean_text, trial_details=trial_details)
        return Response(wav_bytes, mimetype="audio/wav")
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)[:300]}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check — verifies model files exist and Piper loads."""
    model_ok = _is_voice_downloaded(_active_voice)

    piper_ok = _piper_voice is not None
    if not piper_ok and model_ok:
        piper_ok = _load_piper()

    status = "ok" if (model_ok and piper_ok) else "degraded"
    detail = {}
    if not model_ok:
        detail["error"] = f"Model files missing for {_active_voice}"
    elif not piper_ok:
        detail["error"] = _piper_error or "Piper failed to load"

    return jsonify({
        "status": status,
        "voice": _active_voice,
        "model_downloaded": model_ok,
        "piper_loaded": piper_ok,
        **detail,
    }), 200 if (model_ok and piper_ok) else 503


@app.route("/voices", methods=["GET"])
def list_voices():
    """List all configured voice options with download status."""
    # Build list from VOICE_OPTIONS env; always include the active voice
    names = list(VOICE_OPTIONS) if VOICE_OPTIONS else []
    if _active_voice and _active_voice not in names:
        names.insert(0, _active_voice)

    voices = []
    for name in names:
        voices.append({
            "name": name,
            "downloaded": _is_voice_downloaded(name),
            "active": name == _active_voice,
        })

    return jsonify({"voices": voices, "active": _active_voice}), 200


@app.route("/switch-voice", methods=["POST"])
def switch_voice():
    """Switch the active voice. Downloads from HuggingFace if needed.

    Accepts JSON {"voice": "en_US-friday-medium"}.

    Streams SSE progress during download, then loads the model.
      data: {"type":"status","message":"Downloading model..."}
      data: {"type":"download","file":"onnx","percent":50}
      data: {"type":"done","voice":"en_US-friday-medium"}
      data: {"type":"error","message":"..."}
    """
    body = request.get_json(silent=True) or {}
    voice_name = (body.get("voice") or "").strip()

    if not voice_name:
        return jsonify({"error": "No voice name provided"}), 400

    voice_path = _derive_voice_path(voice_name)
    if not voice_path:
        return jsonify({"error": f"Invalid voice name: {voice_name}"}), 400

    def generate():
        global _piper_voice, _active_voice

        # Step 1: Download if not cached
        if not _is_voice_downloaded(voice_name):
            yield f"data: {json.dumps({'type': 'status', 'message': f'Downloading {voice_name}…'})}\n\n"

            onnx_url = f"{_HF_BASE}/{voice_path}/{voice_name}.onnx"
            json_url = f"{_HF_BASE}/{voice_path}/{voice_name}.onnx.json"
            MODEL_DIR.mkdir(parents=True, exist_ok=True)

            for label, url, dest in [
                ("config", json_url, _config_path(voice_name)),
                ("model", onnx_url, _model_path(voice_name)),
            ]:
                yield f"data: {json.dumps({'type': 'download', 'file': label, 'percent': 0})}\n\n"
                try:
                    import urllib.request as req
                    resp = req.urlopen(url)
                    total = int(resp.headers.get('Content-Length', 0))
                    downloaded = 0
                    chunk_size = 65536
                    last_pct = 0

                    with open(str(dest), 'wb') as f:
                        while True:
                            chunk = resp.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                pct = min(99, round(100 * downloaded / total))
                                if pct > last_pct:
                                    last_pct = pct
                                    yield f"data: {json.dumps({'type': 'download', 'file': label, 'percent': pct})}\n\n"

                    size_mb = dest.stat().st_size / 1024 / 1024
                    print(f"[tts] Downloaded {label}: {dest} ({size_mb:.1f} MB)")

                except Exception as e:
                    yield f"data: {json.dumps({'type': 'error', 'message': f'Download failed ({label}): {e}'})}\n\n"
                    return
                yield f"data: {json.dumps({'type': 'download', 'file': label, 'percent': 100})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'status', 'message': f'{voice_name} already downloaded'})}\n\n"

        # Step 2: Load the new voice
        yield f"data: {json.dumps({'type': 'status', 'message': f'Loading {voice_name}…'})}\n\n"
        _piper_voice = None  # Force reload
        if _load_piper(voice_name):
            yield f"data: {json.dumps({'type': 'done', 'voice': voice_name})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'error', 'message': _piper_error or 'Failed to load voice'})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"[tts] Piper TTS service starting on port {PORT}")
    print(f"[tts] Default voice: {VOICE}")
    print(f"[tts] Voice options: {VOICE_OPTIONS or '(none configured — set PIPER_VOICE_OPTIONS)'}")
    print(f"[tts] Model dir: {MODEL_DIR}")

    if not _download_voice(VOICE):
        print("[tts] WARNING: Voice model not available — /synthesize will fail")
    else:
        if _load_piper(VOICE):
            print("[tts] Voice pre-loaded and ready")
        else:
            print(f"[tts] WARNING: Voice load failed — {_piper_error}")

    app.run(host="0.0.0.0", port=PORT, debug=False)
