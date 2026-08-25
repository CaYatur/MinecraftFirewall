"""Generates the application / tray icon from code, so it lives in the repo as something
reviewable and regenerable rather than an opaque binary nobody can edit.

Run:  python tools/make-icon.py
Out:  src/MinecraftFirewall.App/Assets/app.ico  (multi-resolution, 16-256px)

Design notes: a tray icon is judged almost entirely at 16x16, so this deliberately avoids
gradients and fine detail — a solid bright shield on a dark rounded square, with a heavy
checkmark. Everything is drawn at 8x and downsampled, which is what gives the small sizes
usable antialiasing.
"""

from PIL import Image, ImageDraw
import pathlib

SUPERSAMPLE = 8
BACKGROUND = (15, 23, 42, 255)      # slate-900, matches the README banner
SHIELD = (34, 211, 238, 255)        # cyan-400
CHECK = (15, 23, 42, 255)           # punched back out in the background colour

# Shield outline, as fractions of the canvas. Straight segments down to a rounded point —
# enough resolution that the downsampled 16px version still reads as a shield.
SHIELD_OUTLINE = [
    (0.500, 0.105), (0.845, 0.235), (0.845, 0.480),
    (0.835, 0.585), (0.800, 0.680), (0.742, 0.762),
    (0.665, 0.833), (0.578, 0.885), (0.500, 0.915),
    (0.422, 0.885), (0.335, 0.833), (0.258, 0.762),
    (0.200, 0.680), (0.165, 0.585), (0.155, 0.480),
    (0.155, 0.235),
]

CHECK_POINTS = [(0.340, 0.500), (0.452, 0.622), (0.672, 0.378)]


def render(size: int) -> Image.Image:
    canvas = size * SUPERSAMPLE
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    radius = int(canvas * 0.22)
    draw.rounded_rectangle([0, 0, canvas - 1, canvas - 1], radius=radius, fill=BACKGROUND)

    draw.polygon([(x * canvas, y * canvas) for x, y in SHIELD_OUTLINE], fill=SHIELD)

    draw.line(
        [(x * canvas, y * canvas) for x, y in CHECK_POINTS],
        fill=CHECK,
        width=int(canvas * 0.085),
        joint="curve",
    )
    # Round the checkmark's ends; PIL's line joints don't cap the extremities.
    cap = int(canvas * 0.0425)
    for x, y in (CHECK_POINTS[0], CHECK_POINTS[-1]):
        cx, cy = x * canvas, y * canvas
        draw.ellipse([cx - cap, cy - cap, cx + cap, cy + cap], fill=CHECK)

    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent.parent / "src" / "MinecraftFirewall.App" / "Assets" / "app.ico"
    out.parent.mkdir(parents=True, exist_ok=True)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [render(s) for s in sizes]
    frames[-1].save(out, format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[:-1])
    print(f"wrote {out} ({out.stat().st_size} bytes, sizes: {sizes})")


if __name__ == "__main__":
    main()
