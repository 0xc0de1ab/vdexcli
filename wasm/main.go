//go:build js && wasm

// Package main is the WASM entry point for the vdexcli engine.
// It exposes VDEX parsing and explanation functions to JavaScript
// through the syscall/js bridge.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o dist/vdex.wasm ./wasm/
//
// Usage in JavaScript:
//
//	const go = new Go();
//	const result = await WebAssembly.instantiateStreaming(fetch("vdex.wasm"), go.importObject);
//	go.run(result.instance);
//
//	// Then use the API:
//	const fieldMap = window.vdex.explain(uint8Array);   // returns JS object
//	const report   = window.vdex.parse(uint8Array);     // returns JS object
//	const version  = window.vdex.version;               // string
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/0xc0de1ab/vdexcli/pkg/vdex"
)

func main() {
	// Register the API namespace on the global object.
	// All functions are synchronous — JavaScript callers do not need async/await.
	js.Global().Set("vdex", js.ValueOf(map[string]any{
		"explain": js.FuncOf(jsExplain),
		"parse":   js.FuncOf(jsParse),
		"version": js.ValueOf("v0.1.0"),
	}))

	// Block forever — the WASM module must remain alive for callbacks to work.
	select {}
}

// jsExplain implements window.vdex.explain(Uint8Array) → JS Object
//
// Returns a JavaScript object equivalent to the JSON-serialized PrimitiveMap:
//
//	{
//	  "fields": [{ "offset": 0, "size": 4, "type": "magic", "logical_path": "...", ... }],
//	  "total_bytes": 6908,
//	  "unmapped_gaps": []
//	}
//
// On error, returns: { "error": "description" }
func jsExplain(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorObj("explain: expected Uint8Array argument")
	}
	data, ok := jsUint8ArrayToBytes(args[0])
	if !ok {
		return jsErrorObj("explain: argument must be a Uint8Array")
	}

	fm, err := vdex.ExplainBytes(data)
	if err != nil {
		return jsErrorObj("explain: " + err.Error())
	}

	return jsonToJSObject(fm)
}

// jsParse implements window.vdex.parse(Uint8Array) → JS Object
//
// Returns a JavaScript object equivalent to the JSON-serialized VdexReport.
// On error, returns: { "error": "description" }
func jsParse(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorObj("parse: expected Uint8Array argument")
	}
	data, ok := jsUint8ArrayToBytes(args[0])
	if !ok {
		return jsErrorObj("parse: argument must be a Uint8Array")
	}

	r, err := vdex.ParseBytes(data, vdex.WithMeanings())
	if err != nil && r == nil {
		return jsErrorObj("parse: " + err.Error())
	}

	return jsonToJSObject(r)
}

// jsUint8ArrayToBytes converts a JavaScript Uint8Array to a Go []byte.
// Returns (nil, false) if v is not a Uint8Array.
func jsUint8ArrayToBytes(v js.Value) ([]byte, bool) {
	if v.IsNull() || v.IsUndefined() {
		return nil, false
	}
	length := v.Get("length").Int()
	if length < 0 {
		return nil, false
	}
	data := make([]byte, length)
	n := js.CopyBytesToGo(data, v)
	return data[:n], true
}

// jsonToJSObject serializes v to JSON and parses it back into a JavaScript object.
// This is the idiomatic way to convert a Go struct to a JS object via WASM.
func jsonToJSObject(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return jsErrorObj("marshal: " + err.Error())
	}
	// JSON.parse returns a native JS object the browser can introspect directly.
	return js.Global().Get("JSON").Call("parse", string(b))
}

// jsErrorObj creates a JS object { "error": msg } for error propagation.
func jsErrorObj(msg string) any {
	obj := js.Global().Get("Object").New()
	obj.Set("error", msg)
	return obj
}
