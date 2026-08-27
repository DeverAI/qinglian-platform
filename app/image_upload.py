"""Shared secure image validation, compression and storage policy."""

from __future__ import annotations

import io
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile
from PIL import Image, ImageOps, UnidentifiedImageError

from .common import BizError
from .config import ALLOWED_IMAGE_EXT, UPLOAD_DIR
from .security import get_threshold


@dataclass(frozen=True)
class StoredImage:
    filename: str
    stored_bytes: int
    source_bytes: int
    mode: str


def image_policy(points: int) -> dict:
    default_target = get_threshold("threshold_upload_default_target_bytes", 524288)
    min_target = get_threshold("threshold_upload_min_target_bytes", 65536)
    selectable_max = max(default_target, get_threshold("threshold_upload_selectable_max_bytes", 2097152))
    choice_points = get_threshold("threshold_points_upload_quality_choice", 100)
    original_points = get_threshold("threshold_points_upload_original", 500)
    can_choose = points >= choice_points
    presets = sorted({max(min_target, default_target // 2), default_target, selectable_max})
    return {
        "default_target_bytes": default_target,
        "min_target_bytes": min_target,
        "selectable_max_bytes": selectable_max,
        "original_max_bytes": get_threshold("threshold_upload_original_max_bytes", 5242880),
        "source_max_bytes": get_threshold("threshold_upload_source_max_bytes", 10485760),
        "max_dimension": get_threshold("threshold_upload_max_dimension", 1920),
        "max_count": get_threshold("threshold_upload_max_count", 5),
        "choice_points": choice_points,
        "original_points": original_points,
        "can_choose": can_choose,
        "can_original": points >= original_points,
        "presets": [size for size in presets if size <= selectable_max],
    }


def _read_and_validate(file: UploadFile, policy: dict) -> tuple[bytes, Image.Image]:
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_IMAGE_EXT:
        raise BizError(4006, f"不支持的图片格式：{ext}")
    data = file.file.read(policy["source_max_bytes"] + 1)
    file.file.seek(0)
    if len(data) > policy["source_max_bytes"]:
        raise BizError(4007, f"原始图片超过上传上限（{policy['source_max_bytes'] // 1024 // 1024}MB）")
    if len(data) < 12:
        raise BizError(4008, "图片文件过小或已损坏")
    try:
        probe = Image.open(io.BytesIO(data))
        detected = (probe.format or "").upper()
        if detected not in {"JPEG", "PNG", "WEBP"}:
            raise BizError(4009, "图片内容格式无效")
        expected = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".webp": "WEBP"}[ext]
        if detected != expected:
            raise BizError(4009, "图片扩展名与内容不一致")
        width, height = probe.size
        max_pixels = get_threshold("threshold_upload_max_pixels", 24000000)
        if width < 1 or height < 1 or width * height > max_pixels:
            raise BizError(4009, f"图片像素数量超过上限（{max_pixels}）")
        probe.load()
        return data, ImageOps.exif_transpose(probe)
    except BizError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise BizError(4009, "图片解码失败或文件已损坏") from exc


def _encode_webp(image: Image.Image, target_bytes: int, max_dimension: int) -> bytes:
    image = image.convert("RGBA" if image.mode in ("RGBA", "LA") else "RGB")
    image.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)
    current = image
    for _resize_round in range(7):
        for quality in (86, 78, 70, 62, 54, 46, 38, 30):
            output = io.BytesIO()
            current.save(output, format="WEBP", quality=quality, method=4, optimize=True)
            encoded = output.getvalue()
            if len(encoded) <= target_bytes:
                return encoded
        width, height = current.size
        if width <= 320 or height <= 320:
            return encoded
        current = current.resize((max(1, int(width * .82)), max(1, int(height * .82))), Image.Resampling.LANCZOS)
    return encoded


def store_upload_image(file: UploadFile, points: int, requested: str = "auto") -> StoredImage:
    policy = image_policy(points)
    data, image = _read_and_validate(file, policy)
    requested = (requested or "auto").strip().lower()

    if requested == "original":
        if not policy["can_original"]:
            raise BizError(4031, f"保留原图需要至少 {policy['original_points']} 积分")
        if len(data) > policy["original_max_bytes"]:
            raise BizError(4007, f"原图超过保留上限（{policy['original_max_bytes'] // 1024 // 1024}MB）")
        payload = data
        ext = Path(file.filename or "").suffix.lower()
        mode = "original"
    else:
        if requested in ("", "auto"):
            target = policy["default_target_bytes"]
        else:
            if not policy["can_choose"]:
                raise BizError(4031, f"自选压缩大小需要至少 {policy['choice_points']} 积分")
            try:
                target = int(requested)
            except ValueError as exc:
                raise BizError(4001, "压缩目标大小无效") from exc
            if target < policy["min_target_bytes"] or target > policy["selectable_max_bytes"]:
                raise BizError(4001, "压缩目标大小超出 Root 配置范围")
        payload = _encode_webp(image, target, policy["max_dimension"])
        ext = ".webp"
        mode = f"compressed:{target}"

    filename = f"{uuid.uuid4().hex}{ext}"
    (UPLOAD_DIR / filename).write_bytes(payload)
    return StoredImage(filename, len(payload), len(data), mode)
