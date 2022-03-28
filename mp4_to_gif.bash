# original
# ffmpeg -y -i input.mp4 -vf fps=10,scale=716:-1:flags=lanczos,palettegen palette.png
# ffmpeg -i input.mp4 -i palette.png -filter_complex "fps=10,scale=716:-1:flags=lanczos[x];[x][1:v]paletteuse" output.gif

PALETTE=/tmp/palette.png

X_RES="$3"
Y_RES="$4"

# get palette
ffmpeg -y \
    -i "$1" \
    -vf fps=10,scale=$X_RES:$Y_RES:flags=lanczos,palettegen \
    "$PALETTE";

# final conversion
ffmpeg \
    -i "$1" \
    -i "$PALETTE" \
    -filter_complex "fps=10,scale="$X_RES":"$Y_RES":flags=lanczos[x];[x][1:v]paletteuse" \
    "$2";
