#include <brotli/decode.h>
#include <brotli/encode.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const unsigned char input[] = "Brotli 1.2.1 security release round trip";
  const unsigned char invalid[] = {0xff, 0xff, 0xff, 0xff};
  unsigned char compressed[256];
  unsigned char decoded[256];
  size_t compressed_size = sizeof(compressed);
  size_t decoded_size = sizeof(decoded);

  if (BrotliDecoderVersion() != 0x01002001 ||
      BrotliEncoderVersion() != 0x01002001) {
    fprintf(stderr, "Expected Brotli 1.2.1, decoder=%08x encoder=%08x\n",
            BrotliDecoderVersion(), BrotliEncoderVersion());
    return 1;
  }
  if (!BrotliEncoderCompress(6, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC,
                            sizeof(input), input, &compressed_size, compressed) ||
      BrotliDecoderDecompress(compressed_size, compressed, &decoded_size,
                              decoded) != BROTLI_DECODER_RESULT_SUCCESS ||
      decoded_size != sizeof(input) || memcmp(input, decoded, sizeof(input))) {
    fprintf(stderr, "Brotli round trip failed\n");
    return 1;
  }
  decoded_size = sizeof(decoded);
  if (BrotliDecoderDecompress(sizeof(invalid), invalid, &decoded_size, decoded) !=
      BROTLI_DECODER_RESULT_ERROR) {
    fprintf(stderr, "Invalid Brotli input was not rejected\n");
    return 1;
  }
  puts("Brotli 1.2.1: version, round trip and invalid-input checks passed");
  return 0;
}
