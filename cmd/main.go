// Copyright (C) 2023 - Perceval Faramaz
// Portions Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

/*
#include "c_shim.h"
*/
import "C"

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/spf13/pflag"
	"github.com/nowitis/pattern/internal/util"
	"github.com/tillitis/tkeyclient"
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
// Makefile copies the built app here ./app.bin
//
//go:embed app.bin
var appBinary []byte

const (
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "tk1 "
	wantAppName1 = "oath"
)

var le = log.New(os.Stderr, "", 0)

func main() {
	var devPath string
	var speed int
	var otpBundlePath, createOtpBundlePath string
	var helpOnly bool
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.IntVar(&speed, "speed", tkeyclient.SerialSpeed,
		"Set serial port speed in `BPS` (bits per second).")
	pflag.StringVar(&otpBundlePath, "bundle", "",
		"The bundle containing encrypted OTP records.")
	pflag.StringVar(&createOtpBundlePath, "create", "",
		"The path where to create a new bundle.")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, `runoath is a client app that allows to use the TKey as 
a second factor of authentication for the OATH protocol. 

The TKey having no storage, a "bundle" file is used, that contains the OATH records, 
encrypted by the TKey with its device secret. Do not lose this file: only it AND the TKey
it was created with, will allow you to access your OTP codes. 


Usage:

%s`,
			pflag.CommandLine.FlagUsagesWrapped(80))
	}
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}

	if (otpBundlePath == "") && (createOtpBundlePath == "") {
		le.Printf("Please set a OTP bundle path with --bundle, or use --create to generate a new one.\n")
		pflag.Usage()
		os.Exit(2)
	}

	if (otpBundlePath != "") && (createOtpBundlePath != "") {
		le.Printf("--bundle and --create cannot be used together.\n")
		pflag.Usage()
		os.Exit(2)
	}

	if devPath == "" {
		var err error
		devPath, err = util.DetectSerialPort(true)
		if err != nil {
			os.Exit(1)
		}
	}

	tkeyclient.SilenceLogging()

	tk := tkeyclient.New()
	le.Printf("Connecting to device on serial port %s...\n", devPath)
	if err := tk.Connect(devPath, tkeyclient.WithSpeed(speed)); err != nil {
		le.Printf("Could not open %s: %v\n", devPath, err)
		os.Exit(1)
	}

	deviceApp := New(tk)
	exit := func(code int) {
		if err := deviceApp.Close(); err != nil {
			le.Printf("%v\n", err)
		}
		os.Exit(code)
	}
	handleSignals(func() { exit(1) }, os.Interrupt, syscall.SIGTERM)

	if isFirmwareMode(tk) {
		le.Printf("Device is in firmware mode. Loading app...\n")
		if err := tk.LoadApp(appBinary, []byte{}); err != nil {
			le.Printf("LoadApp failed: %v", err)
			exit(1)
		}
	}

	if !isWantedApp(deviceApp) {
		fmt.Printf("The TKey may already be running an app, but not the expected random-app.\n" +
			"Please unplug and plug it in again.\n")
		exit(1)
	}

	var f *os.File
	var err error

	if (otpBundlePath != "") {
		f, err = os.Open(otpBundlePath)
	} else {
		f, err = os.Create(createOtpBundlePath)
	}

	if err != nil {
		le.Printf("%v\n", err)
		exit(1)
	}
	defer f.Close()


	err = deviceApp.LoadToC(nil)
	if err != nil {
		le.Printf("LoadToC failed: %v", err)
		exit(1)
	}

	recordBytes := makePutRequestTOTP("JBSWY3DPEHPK3PXP", "totp.danhersam.com", 30, true, 6)
	err = deviceApp.PutRecord(recordBytes)
	if err != nil {
		le.Printf("PutRecord failed: %v", err)
		exit(1)
	}
	
	encryptedRecordByte, err := deviceApp.GetPutResult((int)(C.secure_oath_record_packed_size()))
	if err != nil {
		le.Printf("GetPutResult failed: %v", err)
		exit(1)
	}

	calculateRequest := makeCalculateRequest(encryptedRecordByte)
	calculated, err := deviceApp.Calculate(calculateRequest)
	if err != nil {
		le.Printf("Calculate failed: %v", err)
		exit(1)
	}
	le.Printf("%i", calculated)

	encToC, err := deviceApp.GetEncryptedToC()
	if err != nil {
		le.Printf("GetEncryptedToC failed: %v", err)
		exit(1)
	}
	le.Printf("%i", len(encToC))

	err = deviceApp.LoadToC(encToC)
	if err != nil {
		le.Printf("LoadToC failed: %v", err)
		exit(1)
	}
	
	listBytes, err := deviceApp.GetList()
	if err != nil {
		le.Printf("GetList failed: %v", err)
		exit(1)
	}
	le.Printf("%i", len(listBytes))
	name := listBytes[1:1+listBytes[0]]
	le.Printf("%s", name)

	f.Write(encToC)
	f.Write(encryptedRecordByte)

	exit(0)
}

func handleSignals(action func(), sig ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
}

func isFirmwareMode(tk *tkeyclient.TillitisKey) bool {
	nameVer, err := tk.GetNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, tkeyclient.ErrResponseStatusNotOK) {
			le.Printf("GetNameVersion failed: %s\n", err)
		}
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantFWName0 &&
		nameVer.Name1 == wantFWName1
}

func isWantedApp(deviceApp OathApp) bool {
	nameVer, err := deviceApp.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantAppName0 &&
		nameVer.Name1 == wantAppName1
}
