#include "aesrng.h"
#include "cpuid.h"

int rand()
{
  if (!intel_has_feature(INTEL_FEATURE_AES)) {
    exit(1);
  }
  if (!intel_has_feature(INTEL_FEATURE_RDSEED)) {
    exit(1);
  }
  return aesrng_get_int32();
}

