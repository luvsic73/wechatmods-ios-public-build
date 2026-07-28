from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageOps


def _component_mask(
    grayscale: Image.Image,
    seed: tuple[int, int],
    *,
    light: bool,
) -> Image.Image:
    threshold = grayscale.point(
        (lambda value: 255 if value >= 128 else 0)
        if light
        else (lambda value: 255 if value < 128 else 0)
    )
    if threshold.getpixel(seed) != 255:
        raise ValueError(f"component seed is outside its mask: {seed}")
    ImageDraw.floodfill(threshold, seed, 128)
    component = threshold.point(lambda value: 255 if value == 128 else 0)
    tone = grayscale if light else ImageOps.invert(grayscale)
    return ImageChops.multiply(component, tone)


def _layer(
    grayscale: Image.Image,
    seeds: list[tuple[int, int]],
    *,
    light: bool,
    color: tuple[int, int, int],
) -> Image.Image:
    alpha = Image.new("L", grayscale.size, 0)
    for seed in seeds:
        alpha = ImageChops.lighter(
            alpha,
            _component_mask(grayscale, seed, light=light),
        )
    if alpha.getbbox() is None:
        raise ValueError("icon layer is empty")
    output = Image.new("RGBA", grayscale.size, (*color, 0))
    output.putalpha(alpha)
    return output


def build_icon_document(source: Path, output: Path) -> None:
    with Image.open(source) as image:
        if image.size != (1024, 1024):
            raise ValueError("reference icon must be 1024x1024")
        grayscale = image.convert("L")

    assets = output / "Assets"
    assets.mkdir(parents=True, exist_ok=True)
    layers = {
        "rear-bubble.png": _layer(
            grayscale,
            [(400, 400)],
            light=True,
            color=(255, 255, 255),
        ),
        "rear-dots.png": _layer(
            grayscale,
            [(305, 345), (500, 345)],
            light=False,
            color=(3, 5, 8),
        ),
        "front-bubble.png": _layer(
            grayscale,
            [(650, 650)],
            light=True,
            color=(255, 255, 255),
        ),
        "front-dots.png": _layer(
            grayscale,
            [(594, 540), (744, 540)],
            light=False,
            color=(3, 5, 8),
        ),
    }
    for name, layer in layers.items():
        layer.save(assets / name, format="PNG", optimize=True)

    document = {
        "fill": {
            "linear-gradient": [
                "srgb:0.03529,0.04706,0.07843,1.00000",
                "srgb:0.00000,0.00000,0.00784,1.00000",
            ]
        },
        "groups": [
            {
                "layers": [
                    {
                        "glass": True,
                        "image-name": "rear-bubble.png",
                        "name": "rear-bubble",
                    },
                    {
                        "image-name": "rear-dots.png",
                        "name": "rear-dots",
                    },
                ],
                "shadow": {"kind": "layer-color", "opacity": 0.35},
                "specular": True,
                "translucency": {"enabled": True, "value": 0.18},
            },
            {
                "layers": [
                    {
                        "glass": True,
                        "image-name": "front-bubble.png",
                        "name": "front-bubble",
                    },
                    {
                        "image-name": "front-dots.png",
                        "name": "front-dots",
                    },
                ],
                "shadow": {"kind": "layer-color", "opacity": 0.42},
                "specular": True,
                "translucency": {"enabled": True, "value": 0.14},
            },
        ],
        "supported-platforms": {
            "circles": ["watchOS"],
            "squares": "shared",
        },
    }
    (output / "icon.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build_icon_document(args.source, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
