// Copyright (C) 2023 - Perceval Faramaz
// Portions Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

/*
#include "c_shim.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
	"time"
	"encoding/base32"
	
	"github.com/tillitis/tkeyclient"
)

var (
	cmdGetNameVersion = appCmd{0x01, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion = appCmd{0x02, "rspGetNameVersion", tkeyclient.CmdLen32}

	cmdLoadToC   = appCmd{0x03, "cmdLoadToC", tkeyclient.CmdLen128}
	rspLoadToC   = appCmd{0x04, "rspLoadToC", tkeyclient.CmdLen4}

	cmdGetList   = appCmd{0x05, "cmdGetList", tkeyclient.CmdLen1}
	rspGetList   = appCmd{0x06, "rspGetList", tkeyclient.CmdLen128}

	cmdGetEncryptedToC   = appCmd{0x07, "cmdGetEncryptedToC", tkeyclient.CmdLen1}
	rspGetEncryptedToC   = appCmd{0x08, "rspGetEncryptedToC", tkeyclient.CmdLen128}
	
	cmdPut   = appCmd{0x09, "cmdPut", tkeyclient.CmdLen128}
	rspPut   = appCmd{0x0a, "rspPut", tkeyclient.CmdLen4}
	
	cmdPutGetRecord = appCmd{0x0b, "cmdPutGetRecord", tkeyclient.CmdLen1}
	rspPutGetRecord = appCmd{0x0c, "rspPutGetRecord", tkeyclient.CmdLen128}

	cmdCalculate = appCmd{0x0d, "cmdCalculate", tkeyclient.CmdLen128}
	rspCalculate = appCmd{0x0e, "rspCalculate", tkeyclient.CmdLen128}
)

type appCmd struct {
	code   byte
	name   string
	cmdLen tkeyclient.CmdLen
}

func (c appCmd) Code() byte {
	return c.code
}

func (c appCmd) CmdLen() tkeyclient.CmdLen {
	return c.cmdLen
}

func (c appCmd) Endpoint() tkeyclient.Endpoint {
	return tkeyclient.DestApp
}

func (c appCmd) String() string {
	return c.name
}


func makePutRequestTOTP(secret string, name string, timestep int, needsTouch bool, digits int) []byte {
	return makePutRecord(secret, name, timestep, true, needsTouch, digits)
}

func makePutRequestHOTP(secret string, name string, counter int, needsTouch bool, digits int) []byte {
	return makePutRecord(secret, name, counter, false, needsTouch, digits)
}

func makePutRecord(secret string, name string, timestepOrCounter int, isTimeBased bool, needsTouch bool, digits int) []byte {
	var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := b32NoPadding.DecodeString(secret)
	if err != nil {
		le.Printf("makePutRecord error: %s\n", err)
		return nil
	}

	key_len := (C.uint8_t)(len(key))

	name_bytes := []byte(name)
	name_len := (C.uint8_t)(len(name_bytes))

	sizeof_oath_record_put_packed := (int)(C.oath_record_put_packed_size())
	oath_record_put_packed := make([]byte, sizeof_oath_record_put_packed)
	
	var isTimeBasedInt C.uint8_t
	if isTimeBased {
	    isTimeBasedInt = 1
	} else {
	    isTimeBasedInt = 0
	}

	var needsTouchInt C.uint8_t
	if needsTouch {
	    needsTouchInt = 1
	} else {
	    needsTouchInt = 0
	}

	C.build_put_command(unsafe.Pointer(&key[0]), key_len, (C.uint64_t)(timestepOrCounter), isTimeBasedInt, needsTouchInt, (C.uint8_t)(digits), unsafe.Pointer(&name_bytes[0]), (C.uint8_t)(name_len), unsafe.Pointer(&oath_record_put_packed[0]))
	
	return oath_record_put_packed
}

func makeCalculateRequest(record []byte) []byte {
	if (len(record) != (int)(C.secure_oath_record_packed_size())) {
		return nil
	}

	sizeof_oath_calculate_packed := (int)(C.oath_calculate_packed_size())
	oath_calculate_packed := make([]byte, sizeof_oath_calculate_packed)

	time := (C.uint64_t)(time.Now().Unix())

	C.build_calculate_command(unsafe.Pointer(&record[0]), (C.ulong)(C.secure_oath_record_packed_size()), time, unsafe.Pointer(&oath_calculate_packed[0]))
	
	return oath_calculate_packed
}


type OathApp struct {
	tk *tkeyclient.TillitisKey // A connection to a TKey
}

// New allocates a struct for communicating with the random app
// running on the TKey. You're expected to pass an existing connection
// to it, so use it like this:
//
//	tk := tkeyclient.New()
//	err := tk.Connect(port)
//	blinker := New(tk)
func New(tk *tkeyclient.TillitisKey) OathApp {
	var blinker OathApp

	blinker.tk = tk

	return blinker
}

// Close closes the connection to the TKey
func (p OathApp) Close() error {
	if err := p.tk.Close(); err != nil {
		return fmt.Errorf("tk.Close: %w", err)
	}
	return nil
}

// GetAppNameVersion gets the name and version of the running app in
// the same style as the stick itself.
func (p OathApp) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tkeyclient.Dump("GetAppNameVersion tx", tx)
	if err = p.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	err = p.tk.SetReadTimeout(2)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	rx, _, err := p.tk.ReadFrame(rspGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	err = p.tk.SetReadTimeout(0)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[2:])

	return nameVer, nil
}

func (p OathApp) LoadToC(tocData []byte) error {
	var offset int
	var err error

	var data []byte
	if len(tocData) == 0 {
		data = make([]byte, 1)
		data[0] = 0
	} else {
		data = tocData
	}
	
	for nsent := 0; offset < len(data); offset += nsent {
		nsent, err = p.sendChunk(cmdLoadToC, rspLoadToC, data[offset:])
		
		if err != nil {
			return fmt.Errorf("SetPattern: %w", err)
		}
	}
	if offset > len(data) {
		return fmt.Errorf("transmitted more than expected")
	}

	return nil
}

// SetPattern loads a LED pattern on the key.
func (p OathApp) PutRecord(data []byte) error {
	var offset int
	var err error

	for nsent := 0; offset < len(data); offset += nsent {
		nsent, err = p.sendChunk(cmdPut, rspPut, data[offset:])
		if err != nil {
			return fmt.Errorf("SetPattern: %w", err)
		}
	}
	if offset > len(data) {
		return fmt.Errorf("transmitted more than expected")
	}

	return nil
}

func (p OathApp) sendChunk(cmd appCmd, rsp appCmd, content []byte) (int, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmd, id)
	if err != nil {
		return 0, fmt.Errorf("NewFrameBuf: %w", err)
	}

	payload := make([]byte, cmd.CmdLen().Bytelen()-1)
	copied := copy(payload, content)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	copy(tx[2:], payload)

	tkeyclient.Dump("sendChunk tx", tx)
	if err = p.tk.Write(tx); err != nil {
		return 0, fmt.Errorf("Write: %w", err)
	}

	// Wait for reply
	rx, _, err := p.tk.ReadFrame(rsp, id)
	if err != nil {
		return 0, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[2] != tkeyclient.StatusOK {
		return 0, fmt.Errorf("putSendChunk NOK")
	}
	le.Printf("bb %i", copied)
	return copied, nil
}

// GetPattern retrieves the LED pattern from the key.
func (p OathApp) GetPutResult(objectSize int) ([]byte, error) {
	id := 2
	payload := make([]byte, objectSize)

	for nreceivedBytes := 0; nreceivedBytes < objectSize; {
		tx, err := tkeyclient.NewFrameBuf(cmdPutGetRecord, id)
		if err != nil {
			return nil, fmt.Errorf("NewFrameBuf: %w", err)
		}

		tkeyclient.Dump("GetPattern tx", tx)
		if err = p.tk.Write(tx); err != nil {
			return nil, fmt.Errorf("Write: %w", err)
		}
		
		rx, _, err := p.tk.ReadFrame(rspPutGetRecord, id)
		if err != nil {
			return nil, fmt.Errorf("ReadFrame: %w", err)
		}

		if rx[2] != tkeyclient.StatusOK {
			return nil, fmt.Errorf("getSig NOK")
		}
		
		nreceivedBytes += copy(payload[nreceivedBytes:], rx[3:])
	}

	return payload, nil
}

func (p OathApp) GetEncryptedToC() ([]byte, error) {
	id := 2
	var payload []byte

	objectSize := 1
	for nreceivedBytes := 0; nreceivedBytes < objectSize; {
		tx, err := tkeyclient.NewFrameBuf(cmdGetEncryptedToC, id)
		if err != nil {
			return nil, fmt.Errorf("NewFrameBuf: %w", err)
		}

		tkeyclient.Dump("GetPattern tx", tx)
		if err = p.tk.Write(tx); err != nil {
			return nil, fmt.Errorf("Write: %w", err)
		}
		
		rx, _, err := p.tk.ReadFrame(rspGetEncryptedToC, id)
		if err != nil {
			return nil, fmt.Errorf("ReadFrame: %w", err)
		}

		if rx[2] != tkeyclient.StatusOK {
			return nil, fmt.Errorf("getSig NOK")
		}

		if nreceivedBytes == 0 {
			objectSize = (int)(rx[3])
			objectSize *= (int)(C.toc_record_descriptor_packed_size())
			objectSize += (int)(C.decrypted_toc_header_packed_size())
			payload = make([]byte, objectSize)
		}
		
		nreceivedBytes += copy(payload[nreceivedBytes:], rx[3:])
	}

	return payload, nil
}

func (p OathApp) GetList() ([]byte, error) {
	id := 2
	var payload []byte

	objectSize := 1
	for nreceivedBytes := 0; nreceivedBytes < objectSize; {
		tx, err := tkeyclient.NewFrameBuf(cmdGetList, id)
		if err != nil {
			return nil, fmt.Errorf("NewFrameBuf: %w", err)
		}

		tkeyclient.Dump("GetPattern tx", tx)
		if err = p.tk.Write(tx); err != nil {
			return nil, fmt.Errorf("Write: %w", err)
		}
		
		rx, _, err := p.tk.ReadFrame(rspGetList, id)
		if err != nil {
			return nil, fmt.Errorf("ReadFrame: %w", err)
		}

		if rx[2] == 0 {
			return nil, nil
		}

		if nreceivedBytes == 0 {
			objectSize = (int)(rx[2])
			objectSize *= (int)(C.toc_record_descriptor_packed_size())
			payload = make([]byte, objectSize)
		}
		
		nreceivedBytes += copy(payload[nreceivedBytes:], rx[3:])
	}

	return payload, nil
}

func (p OathApp) Calculate(request []byte) (uint32, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdCalculate, id)
	if err != nil {
		return 0, fmt.Errorf("NewFrameBuf: %w", err)
	}

	payload := make([]byte, cmdCalculate.CmdLen().Bytelen()-1)
	copied := copy(payload, request)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	copy(tx[2:], payload)

	tkeyclient.Dump("Calculate tx", tx)
	if err = p.tk.Write(tx); err != nil {
		return 0, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := p.tk.ReadFrame(rspCalculate, id)
	if err != nil {
		return 0, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[2] != tkeyclient.StatusOK {
		return 0, fmt.Errorf("getSig NOK")
	}

	code := uint32(rx[3]) | uint32(rx[4])<<8 | uint32(rx[5])<<16 | uint32(rx[6])<<24
	
	return code, nil
}

