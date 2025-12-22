from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

import numpy as np
from PIL import Image, ImageFilter, ImageOps
from scipy.ndimage import gaussian_filter, label


@dataclass(frozen=True)
class Box:
    x0: int
    y0: int
    x1: int
    y1: int

    def as_tuple(self) -> Tuple[int, int, int, int]:
        return (self.x0, self.y0, self.x1, self.y1)


def _normalize01(a: np.ndarray) -> np.ndarray:
    amin = float(a.min())
    amax = float(a.max())
    return (a - amin) / (amax - amin + 1e-9)


def _gradient_magnitude(img: np.ndarray, sigma: float = 3.0) -> np.ndarray:
    # mimic original logic: abs diff with prepend on x and y
    gx = np.abs(np.diff(img, axis=1, prepend=img[:, :1]))
    gy = np.abs(np.diff(img, axis=0, prepend=img[:1, :]))
    mag = gaussian_filter(gx + gy, sigma=sigma)
    return _normalize01(mag)


def locate_mosaic_region(frame: np.ndarray, percentile: float = 30.0) -> Box:
    mag = _gradient_magnitude(frame, sigma=3.0)
    thresh = np.percentile(mag, percentile)
    mask = mag < thresh

    labeled, n = label(mask)
    if n == 0:
        h, w = frame.shape
        return Box(0, 0, w, h)

    # largest component
    counts = np.bincount(labeled.ravel())
    counts[0] = 0  # ignore background
    lab = int(np.argmax(counts))

    ys, xs = np.where(labeled == lab)
    return Box(int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def _crop(img: np.ndarray, box: Box) -> np.ndarray:
    return img[box.y0 : box.y1, box.x0 : box.x1]


def _valid_region_bounds(h: int, w: int, B: int, ox: int, oy: int) -> Tuple[int, int]:
    y_end = oy + ((h - oy) // B) * B
    x_end = ox + ((w - ox) // B) * B
    return y_end, x_end


def pick_best_grid_offset(crop: np.ndarray, B: int) -> Tuple[int, int]:
    h, w = crop.shape
    best = (0, 0)
    best_score: float | None = None

    for oy in range(B):
        y_end, _ = _valid_region_bounds(h, w, B, 0, oy)
        if y_end <= oy:
            continue
        for ox in range(B):
            _, x_end = _valid_region_bounds(h, w, B, ox, 0)
            if x_end <= ox:
                continue

            region = crop[oy:y_end, ox:x_end]
            ny = (y_end - oy) // B
            nx = (x_end - ox) // B

            blocks = region.reshape(ny, B, nx, B)
            means = blocks.mean(axis=(1, 3), keepdims=True)
            mse = float(np.mean((blocks - means) ** 2))

            if best_score is None or mse < best_score:
                best_score = mse
                best = (ox, oy)

    return best


def extract_observations(crop: np.ndarray, B: int) -> List[Tuple[int, int, float]]:
    h, w = crop.shape
    ox, oy = pick_best_grid_offset(crop, B)
    y_end, x_end = _valid_region_bounds(h, w, B, ox, oy)

    obs: List[Tuple[int, int, float]] = []
    for y in range(oy, y_end, B):
        for x in range(ox, x_end, B):
            block = crop[y : y + B, x : x + B]
            obs.append((y, x, float(block.mean())))
    return obs


def iterative_recstruct(
    frames: Sequence[np.ndarray],
    box: Box,
    B: int = 16,
    iters: int = 20,
    alpha: float = 0.7,
) -> np.ndarray:
    crops = [_crop(f, box) for f in frames]
    observations = [extract_observations(c, B) for c in crops]

    X = np.mean(crops, axis=0).astype(np.float32, copy=False)

    for _ in range(iters):
        for obs_list in observations:
            for y, x, target_mean in obs_list:
                blk = X[y : y + B, x : x + B]
                cur_mean = float(blk.mean())
                X[y : y + B, x : x + B] = blk + (target_mean - cur_mean) * alpha

    # normalize to uint8 like original
    X = X - float(X.min())
    mx = float(X.max())
    if mx > 0:
        X = X / mx * 255.0
    return X.astype(np.uint8)


def load_frames_gray(path: str) -> List[np.ndarray]:
    img = Image.open(path)
    n = getattr(img, "n_frames", 1)
    out: List[np.ndarray] = []
    for i in range(n):
        img.seek(i)
        out.append(np.array(img.convert("L"), dtype=np.float32))
    return out


def save_outputs(rec_u8: np.ndarray) -> None:
    base = Image.fromarray(rec_u8)
    base.save("rec.png")

    ac = ImageOps.autocontrast(base)
    ac.save("rec_ac.png")

    sharp = ac.filter(ImageFilter.SHARPEN)
    sharp.save("rec_ac_sharp.png")


def main() -> int:
    if len(sys.argv) < 2:
        return 1

    frames = load_frames_gray(sys.argv[1])
    bbox = locate_mosaic_region(frames[0])

    rec = iterative_recstruct(frames, bbox, B=16, iters=20, alpha=0.7)
    save_outputs(rec)

    print("Saved: rec.png, rec_ac.png, rec_ac_2.png")
    print("Crop box:", bbox.as_tuple())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
