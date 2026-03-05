// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using PCSC;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace CtapDotNet.Transports.Nfc
{
    public class PcscNfcSecurityKeyDevice : FidoSecurityKeyDevice
    {
        private readonly PcscSecurityKeyReaderDevice _readerDevice;
        private EventHandler<UserActionRequiredEventArgs> _userActionRequiredEventHandler;

        public override EventHandler<UserActionRequiredEventArgs> UserActionRequiredEventHandler
        {
            get
            {
                return _userActionRequiredEventHandler;
            }

            set
            {
                _userActionRequiredEventHandler = value;
            }
        }

        public override DeviceInfo DeviceInfo
        {
            get
            {
                return new DeviceInfo(_readerDevice.CardId, _readerDevice.ReaderName, _readerDevice.ReaderName, Transports.NFC, _readerDevice.IsCardOnReader());
            }
        }

        internal PcscNfcSecurityKeyDevice(PcscSecurityKeyReaderDevice readerDevice)
        {
            _readerDevice = readerDevice;
        }

        public override byte[] Send(byte[] data)
        {
            return _readerDevice.Send(data);
        }

        public override void WaitForRemoval()
        {
            while (_readerDevice.IsCardOnReader())
            {
                Task.Delay(500);
            }
        }
    }

    internal class PcscSecurityKeyReaderDevice
    {
        private static readonly byte[] FidoAid = new byte[]
        {
            0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
        };

        public readonly string ReaderName;
        public readonly string CardId;

        public PcscSecurityKeyReaderDevice(string readerName)
        {
            ReaderName = readerName;
            CardId = ReadCardId();
        }

        public static IEnumerable<PcscSecurityKeyReaderDevice> AllDevices
        {
            get
            {
                PcscSecurityKeyReaderDevice readerDevice = null;
                using (var context = new SCardContext())
                {
                    context.Establish(SCardScope.System);

                    var readers = context.GetReaders();
                    foreach (var readerName in readers)
                    {
                        using (var reader = new SCardReader(context))
                        {
                            var rc = reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                            if (rc != SCardError.Success)
                            {
                                continue;
                            }

                            try
                            {
                                TrySelectingFidoApplet(reader);
                                readerDevice = new PcscSecurityKeyReaderDevice(readerName);
                            }
                            catch
                            {
                                readerDevice = null;
                            }
                            finally
                            {
                                try { reader.Disconnect(SCardReaderDisposition.Leave); } catch { }
                            }

                            if (readerDevice != null)
                            {
                                yield return readerDevice;
                            }
                        }
                    }
                }
            }
        }

        public bool IsConnected
        {
            get
            {
                try
                {
                    using (var context = new SCardContext())
                    {
                        context.Establish(SCardScope.System);

                        var readers = context.GetReaders();
                        foreach (var readerName in readers)
                        {
                            if (readerName == ReaderName)
                            {
                                return true;
                            }
                        }
                    }
                }
                catch { }
                return false;
            }
        }

        private static void TrySelectingFidoApplet(SCardReader reader)
        {
            var receiveBuffer = new byte[256];

            var statucCode = reader.Transmit(
                SCardPCI.GetPci(reader.ActiveProtocol),
                new CommandApdu(IsoCase.Case4Short, reader.ActiveProtocol)
                {
                    CLA = 0x00,
                    INS = 0xA4,
                    P1 = 0x04,
                    P2 = 0x00,
                    Data = FidoAid
                }.ToArray(),
                ref receiveBuffer);

            if (statucCode != SCardError.Success)
            {
                throw new Exception($"PCSC transmit failed. Status code {statucCode}");
            }

            var response = new ResponseApdu(receiveBuffer, IsoCase.Case4Short, reader.ActiveProtocol);

            if (response.StatusWord != 0x9000)
            {
                throw new Exception($"FIDO applet selection failed. Status code: {response.StatusWord}");
            }
        }

        public byte[] Send(byte[] packet)
        {
            using (var scardContext = new SCardContext())
            {
                scardContext.Establish(SCardScope.System);
                using (var scardReader = new SCardReader(scardContext))
                {
                    byte[] response;

                    var statusCode = scardReader.Connect(ReaderName, SCardShareMode.Shared, SCardProtocol.T0 | SCardProtocol.T1);
                    if (statusCode != SCardError.Success)
                        throw new Exception($"Failed to connect to the card. Status code: {statusCode}");

                    try
                    {
                        TrySelectingFidoApplet(scardReader);
                        response = SendCtap(scardReader, packet);
                    }
                    finally
                    {
                        try { scardReader.Disconnect(SCardReaderDisposition.Leave); } catch { }
                    }

                    if (response == null || response.Length == 0)
                        throw new Exception("Empty CTAP2 NFC response.");

                    return response;
                }
            }
        }

        private string ReadCardId()
        {
            using (var scardContext = new SCardContext())
            {
                scardContext.Establish(SCardScope.System);
                using (var scardReader = new SCardReader(scardContext))
                {
                    var statusCode = scardReader.Connect(ReaderName, SCardShareMode.Shared, SCardProtocol.T0 | SCardProtocol.T1);
                    if (statusCode != SCardError.Success)
                        throw new Exception($"Failed to connect to the card. Status code: {statusCode}");

                    byte[] sendBuffer = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
                    byte[] receiveBuffer = new byte[10];
                    statusCode = scardReader.Transmit(sendBuffer, ref receiveBuffer);
                    if (statusCode != SCardError.Success)
                    {
                        throw new Exception($"Failed to transmit APDU. Error code: {statusCode}");
                    }

                    return ExtractUid(receiveBuffer.ToHexString());
                }
            }
        }

        public bool IsCardOnReader()
        {
            if (!IsConnected)
            {
                return false;
            }

            try
            {
                return ReadCardId() == CardId;
            }
            catch { return false; }
        }


        private static string ExtractUid(string rawUid)
        {
            int index = -1;
            for (int i = rawUid.Length - 2; i >= 0; i -= 2)
            {
                if (rawUid.Substring(i, 2) == "90")
                {
                    index = i;
                    break;
                }
            }

            return rawUid.Substring(0, index);
        }

        private byte[] SendCtap(SCardReader scardReader, byte[] ctapMessage)
        {
            const int MaxShortLc = 251;

            int offset = 0;

            byte[] responseBytes = null;

            while (offset < ctapMessage.Length)
            {
                int remaining = ctapMessage.Length - offset;
                int chunkLen = Math.Min(MaxShortLc, remaining);
                bool more = (offset + chunkLen) < ctapMessage.Length;

                byte cla = (byte)(0x80 | (more ? 0x10 : 0x00));
                byte ins = 0x10;
                byte p1 = 0x00;
                byte p2 = 0x00;

                var chunk = new byte[chunkLen];
                Buffer.BlockCopy(ctapMessage, offset, chunk, 0, chunkLen);

                var apdu = BuildShortApdu(cla, ins, p1, p2, chunk, le: 0x00);

                responseBytes = TransmitApdu(scardReader, apdu);

                if (responseBytes == null || responseBytes.Length < 2)
                    throw new Exception("Truncated APDU response during command chaining.");

                ushort swChunk = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);
                if (more)
                {
                    if (swChunk != 0x9000)
                        throw new Exception($"Card returned error during command chaining: 0x{swChunk:X4}");
                    responseBytes = null;
                }

                offset += chunkLen;
            }

            // After last command block, responseBytes holds the response APDU to the final block.
            if (responseBytes == null)
                throw new Exception("No response received for final chained APDU block.");

            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    if (responseBytes.Length < 2) throw new Exception("Truncated APDU response.");

                    ushort sw = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);
                    byte sw1 = (byte)(sw >> 8);
                    byte sw2 = (byte)(sw & 0xFF);

                    if (responseBytes.Length > 2)
                    {
                        ms.Write(responseBytes, 0, responseBytes.Length - 2);
                    }

                    if (sw == 0x9000) break;

                    // CTAP GetResponse Loop (9100)
                    if (sw == 0x9100)
                    {
                        // GET NEXT RESPONSE as SHORT APDU (no extended)
                        var getNext = BuildShortApdu(0x80, 0x11, 0x00, 0x00, null, le: 0x00);
                        responseBytes = TransmitApdu(scardReader, getNext);
                        continue;
                    }

                    // ISO GetResponse Loop (61xx)
                    if (sw1 == 0x61)
                    {
                        int le = (sw2 == 0x00) ? 256 : sw2;
                        // Standard ISO GET RESPONSE: CLA=00, INS=C0
                        byte[] isoGet = new byte[] { 0x00, 0xC0, 0x00, 0x00, (byte)(le & 0xFF) };
                        responseBytes = TransmitApdu(scardReader, isoGet);
                        continue;
                    }

                    throw new Exception($"Card returned an error. Status code: 0x{sw:X4}");
                }

                return ms.ToArray();
            }
        }

        private byte[] BuildShortApdu(byte cla, byte ins, byte p1, byte p2, byte[] data, byte? le)
        {
            int dataLen = data?.Length ?? 0;
            if (dataLen > 251) throw new ArgumentOutOfRangeException(nameof(data), "Short APDU data cannot exceed 255 bytes.");

            bool hasData = dataLen > 0;
            bool hasLe = le.HasValue;

            int len =
                4 +
                (hasData ? 1 + dataLen : 0) +
                (hasLe ? 1 : 0);

            var apdu = new byte[len];
            apdu[0] = cla;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;

            int idx = 4;

            if (hasData)
            {
                apdu[idx++] = (byte)dataLen;
                Buffer.BlockCopy(data, 0, apdu, idx, dataLen);
                idx += dataLen;
            }

            if (hasLe)
            {
                apdu[idx++] = le.Value;
            }

            return apdu;
        }

        private static byte[] TransmitApdu(SCardReader scardReader, byte[] command)
        {
            IntPtr sendPci = SCardPCI.GetPci(scardReader.ActiveProtocol);
            byte[] receiveBuffer = new byte[8192];
            int receiveLength = receiveBuffer.Length;
            var statusCode = scardReader.Transmit(sendPci, command, command.Length, null, receiveBuffer, ref receiveLength);

            if (statusCode != SCardError.Success)
            {
                throw new Exception($"PCSC transmit failed. Status code: {statusCode}");
            }

            byte[] result = new byte[receiveLength];
            Buffer.BlockCopy(receiveBuffer, 0, result, 0, receiveLength);
            return result;
        }
    }
}
