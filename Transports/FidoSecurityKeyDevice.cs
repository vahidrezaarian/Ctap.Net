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

    public abstract class FidoSecurityKeyDevice: IDisposable
    {
        public DeviceInfo DeviceInfo;
        public object Device;
        public abstract EventHandler<EventArgs> UserActionRequiredEventHandler { get; set; }

        public abstract void Dispose();

        public abstract byte[] Send(byte[] data);
	}

    public static class FidoSecurityKeyDevices
    {
        public static IEnumerable<FidoSecurityKeyDevice> AllDevices
        {
            get
            {
                foreach (var device in UsbFidoHidDevice.AllDevices)
                {
                    yield return new UsbSecurityKeyDevice(device) { DeviceInfo = new DeviceInfo(device.GetProductName(), device.DevicePath, Transports.USB), Device = device };
                }

                foreach (var device in PcscSecurityKeyReaderDevice.AllDevices)
                {
                    yield return new PcscNfcSecurityKeyDevice(device) { DeviceInfo = new DeviceInfo(device, device, Transports.NFC), Device = device };   
                }

                foreach (var device in CcidSecurityKeyReaderDevice.AllDevices)
                {
                    yield return new CcidNfcSecurityKeyDevice(device) { DeviceInfo = new DeviceInfo(device.Name, device.DevicePath, Transports.NFC), Device = device };
                }
			}
        }
    }

    public class DeviceInfo
    {
        public readonly string Name;
        public readonly string Path;
        public readonly Transports Transport;

        public DeviceInfo(string name, string path, Transports transport)
        {
            Name = name;
            Path = path;
            Transport = transport;
        }
    }
}
