#include <stdint.h>
#include <stdlib.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten/emscripten.h>

extern "C" {

// The prebuilt openssl-wasm archives are wasm32-wasi flavored.
// Provide minimal shims so they can be linked by emscripten for now.
int errno = 0;
int _CLOCK_REALTIME = 0;

EM_JS(int, zsign_fill_random, (uint8_t* buf, int buflen), {
	if (buflen <= 0) {
		return 0;
	}
	if (typeof require === 'function') {
		try {
			const crypto = require('crypto');
			const bytes = crypto.randomBytes(buflen);
			HEAPU8.set(bytes, buf);
			return buflen;
		} catch (e) {}
	}
	if (typeof globalThis !== 'undefined' &&
		globalThis.crypto &&
		typeof globalThis.crypto.getRandomValues === 'function') {
		const view = HEAPU8.subarray(buf, buf + buflen);
		globalThis.crypto.getRandomValues(view);
		return buflen;
	}
	return -1;
});

long getrandom(void* buf, unsigned long buflen, unsigned int flags)
{
	(void)flags;
	if (!buf || buflen == 0) {
		return 0;
	}
	if (buflen > 0x7fffffffUL) {
		buflen = 0x7fffffffUL;
	}
	return (long)zsign_fill_random((uint8_t*)buf, (int)buflen);
}

void arc4random_buf(void* buf, size_t len)
{
	uint8_t* p = (uint8_t*)buf;
	size_t offset = 0;
	while (offset < len) {
		long ret = getrandom(p + offset, (unsigned long)(len - offset), 0);
		if (ret <= 0) {
			abort();
		}
		offset += (size_t)ret;
	}
}

}
#endif
