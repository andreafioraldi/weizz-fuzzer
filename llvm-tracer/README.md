# Weizz LLVM Tracer

Use weizz-clang and weizz-clang++ compiler wrappers to cimpile your target.

Use WEIZZ_CC_VER to set a a compiler version (e.g. 8 for clang-8) or set manually the underlying compiler using WEIZZ_C_COMPILER and WEIZZ_CXX_COMPILER env vars.

To enable sanitization, use WEIZZ_CC_ASAN, WEIZZ_CC_MSAN, WEIZZ_CC_UBSAN.

## Persistent mode

```c
int main() {

  __WEIZZ_INIT();
  
  while (__WEIZZ_LOOP(1000000)) {
  
    target();
  
  }

}
```
