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
//	const fieldMap = window.vdex.explain(uint8Array);          // returns JS object
//	const structure = window.vdex.explainStructure(uint8Array); // compact web DTO object
//	const json = window.vdex.explainStructureJSON(uint8Array);   // compact JSON text
//	const report = window.vdex.parse(uint8Array);               // returns JS object
//	const version = window.vdex.version;                        // string
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/0xc0de1ab/vdexcli/pkg/vdex"
)

type structureField struct {
	Offset      uint32         `json:"offset"`
	Size        uint32         `json:"size"`
	Type        vdex.FieldType `json:"type"`
	ParsedValue any            `json:"parsed_value,omitempty"`
	LogicalPath string         `json:"logical_path"`
	Description string         `json:"description,omitempty"`
}

func main() {
	// Register the API namespace on the global object.
	// All functions are synchronous — JavaScript callers do not need async/await.
	js.Global().Set("vdex", js.ValueOf(map[string]any{
		"explain":              js.FuncOf(jsExplain),
		"explainStructure":     js.FuncOf(jsExplainStructure),
		"explainStructureJSON": js.FuncOf(jsExplainStructureJSON),
		"parse":                js.FuncOf(jsParse),
		"version":              js.ValueOf(vdex.Version()),
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

// jsExplainStructure preserves the public object-returning API.
func jsExplainStructure(_ js.Value, args []js.Value) any {
	payload, err := buildStructureJSON(args)
	if err != nil {
		return jsErrorObj("explainStructure: " + err.Error())
	}
	return js.Global().Get("JSON").Call("parse", string(payload))
}

// jsExplainStructureJSON returns compact JSON text for the browser worker. Text
// avoids cloning the complete field slice across the Go-to-JavaScript bridge.
func jsExplainStructureJSON(_ js.Value, args []js.Value) any {
	payload, err := buildStructureJSON(args)
	if err != nil {
		return jsErrorObj("explainStructureJSON: " + err.Error())
	}
	return string(payload)
}

func buildStructureJSON(args []js.Value) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("expected Uint8Array argument")
	}
	data, ok := jsUint8ArrayToBytes(args[0])
	if !ok {
		return nil, fmt.Errorf("argument must be a Uint8Array")
	}

	fm, err := vdex.ExplainBytes(data)
	if err != nil {
		return nil, err
	}

	payload, err := marshalStructureMap(fm)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return payload, nil
}

func marshalStructureMap(fm *vdex.FieldMap) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(min(len(fm.Fields)*128, 64<<20))
	out.WriteString(`{"fields":[`)
	encoder := json.NewEncoder(&out)
	written := 0
	for _, field := range fm.Fields {
		if field == nil {
			continue
		}
		parsedValue := field.ParsedValue
		if field.Type == vdex.TypeBytes || field.Type == vdex.TypePadding {
			parsedValue = nil
		}
		if written > 0 {
			out.WriteByte(',')
		}
		if err := encoder.Encode(structureField{
			Offset:      field.Offset,
			Size:        field.Size,
			Type:        field.Type,
			ParsedValue: parsedValue,
			LogicalPath: field.LogicalPath,
			Description: field.Description,
		}); err != nil {
			return nil, fmt.Errorf("field %d: %w", written, err)
		}
		written++
	}
	out.WriteString(`],"total_bytes":`)
	fmt.Fprintf(&out, "%d", fm.TotalBytes)
	out.WriteString(`,"unmapped_gaps":`)
	if err := encoder.Encode(fm.UnmappedGaps); err != nil {
		return nil, fmt.Errorf("unmapped gaps: %w", err)
	}
	out.WriteString(`,"dex_previews":`)
	if err := encoder.Encode(fm.DexPreviews); err != nil {
		return nil, fmt.Errorf("DEX previews: %w", err)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
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
