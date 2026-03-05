// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using CtapDotNet.Transports.Nfc;
using CtapDotNet.Transports.Usb;
using System;
using System.Collections.Generic;

namespace CtapDotNet.Transports
{
    public enum Transports
    {
        USB,
        NFC,
        BLE
    }

    public abstract class FidoSecurityKeyDevice
    {
        public abstract EventHandler<UserActionRequiredEventArgs> UserActionRequiredEventHandler { get; set; }
        public abstract DeviceInfo DeviceInfo { get; }

        public abstract byte[] Send(byte[] data);
        public abstract void WaitForRemoval();
    }

    public static class FidoSecurityKeyDevices
    {
        public static IEnumerable<FidoSecurityKeyDevice> AllDevices
        {
            get
            {
                foreach (var device in UsbFidoHidDevice.AllDevices)
                {
                    yield return new UsbSecurityKeyDevice(device);
                }

                foreach (var device in PcscSecurityKeyReaderDevice.AllDevices)
                {
                    yield return new PcscNfcSecurityKeyDevice(device);
                }

                foreach (var device in CcidSecurityKeyReaderDevice.AllDevices)
                {
                    yield return new CcidNfcSecurityKeyDevice(device);
                }
            }
        }
    }

    public class DeviceInfo
    {
        public readonly string SerialNumber;
        public readonly string Name;
        public readonly string Path;
        public readonly Transports Transport;
        public readonly bool IsPresent;

        public DeviceInfo(string serialNumber, string name, string path, Transports transport, bool isPresent)
        {
            SerialNumber = serialNumber;
            Name = name;
            Path = path;
            Transport = transport;
            IsPresent = isPresent;
        }
    }
}
