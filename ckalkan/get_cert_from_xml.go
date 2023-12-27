package ckalkan

import "C"
import (
	"fmt"
	"unsafe"
)

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include "KalkanCrypt.h"
//
// unsigned long KC_getCertFromXML(char *inXML, int inXMLLength, int inSignId, int flags, char *outCert, int *outCertLength) {
//     return kc_funcs->KC_getCertFromXML(inXML, inXMLLength, inSignId, flags, outCert, outCertLength);
// }

// getCertFromCMS обеспечивает получение сертификата из xml.
func (cli *Client) GetCertFromXML(xml string, signID int, flag Flag) (cert string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if err != nil {
				err = fmt.Errorf("%w: panic: %s", err, r)
				return
			}

			err = fmt.Errorf("%w: %s", ErrPanic, r)
		}
	}()

	cli.mu.Lock()
	defer cli.mu.Unlock()

	cXml := C.CString(xml)
	defer C.free(unsafe.Pointer(cXml))

	outCertLen := 32768
	outCert := C.malloc(C.ulong(C.sizeof_uchar * outCertLen))
	defer C.free(outCert)

	rc := int(C.KC_getCertFromXML(
		cXml,
		C.int(len(cms)),
		C.int(signID),
		C.int(int(flag)),
		(*C.char)(outCert),
		(*C.int)(unsafe.Pointer(&outCertLen)),
	))

	err = cli.wrapError(rc)
	if err != nil {
		return cert, err
	}

	cert = C.GoString((*C.char)(outCert))

	return cert, nil
}
