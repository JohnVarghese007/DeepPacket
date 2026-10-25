set -e

sanitizer="${1:-OFF}"
build_dir="${2:-build}"

rm -rf "$build_dir"
cmake -B "$build_dir" -S . -DDEEPPACKET_SANITIZER="$sanitizer"
cmake --build "$build_dir" -j