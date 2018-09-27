#include <MagickWand/MagickWand.h>
#include <stdio.h>
#include <stdlib.h>

#define ThrowWandException(wand) \
    { \
        char* description; \
\
        ExceptionType severity; \
\
        description = MagickGetException(wand, &severity); \
        (void) fprintf(stderr, "%s %s %lu %s\n", GetMagickModule(), description); \
        description = (char*) MagickRelinquishMemory(description); \
        exit(-1); \
    }

#define SigmoidalContrast(x) \
  (QuantumRange*(1.0/(1+exp(10.0*(0.5-QuantumScale*x)))-0.0066928509)*1.0092503)

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s image thumbnail\n", argv[0]);
        exit(EXIT_SUCCESS);
    }
    MagickWandGenesis();
    MagickWand* magick_wand = NewMagickWand();
    MagickBooleanType status = MagickReadImage(magick_wand, argv[1]);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }

    PixelIterator* iterator = NewPixelIterator(magick_wand);
    if (!iterator) {
        ThrowWandException(magick_wand);
    }
    int x;
    int y;
    PixelWand **pixels;
    PixelInfo pixel;
    for (y = 0; y < (long) MagickGetImageHeight(magick_wand); y++) {
        size_t width;
        pixels = PixelGetNextIteratorRow(iterator, &width);
        if (!pixels) {
            break;
        }
        for (x = 0; x < (long) width; x++) {
            PixelGetMagickColor(pixels[x], &pixel);
            pixel.red = SigmoidalContrast(pixel.red);
            pixel.green = SigmoidalContrast(pixel.green);
            pixel.blue = SigmoidalContrast(pixel.blue);
            pixel.index = SigmoidalContrast(pixel.index);
            PixelSetMagickColor(pixels[x], &pixel);
        }
        PixelSyncIterator(iterator);
    }
    if (y < (long) MagickGetImageHeight(magick_wand)) {
        ThrowWandException(magick_wand);
    }
    iterator = DestroyPixelIterator(iterator);
    magick_wand = DestroyMagickWand(magick_wand);

    status = MagickWriteImages(magick_wand, argv[2], MagickTrue);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }
    MagickWandTerminus();

    return EXIT_SUCCESS;
}
