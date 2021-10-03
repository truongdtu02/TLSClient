using Microsoft.Extensions.DependencyInjection;
using NetCoreServer;
using System;
using Security;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Net.Sockets;
using System.Timers;
using TcpClient = NetCoreServer.TcpClient;
using System.Threading;

namespace TLSClient
{
    class TLSClient : TcpClient
    {
        //debug
        const int CONNECT_TIMEOUT = 1000000; //10s, maximum time for establish TCP TLS handshake
        const int KEEP_ALIVE_INTERVAL = 10000000; //send keep alive packet every 60s
        internal bool IsHandshaked { get; private set; } //get successfull ACK
        System.Timers.Timer timer;
        internal long ConnectedTime { get; private set; }
        private readonly ILogger<TLSClient> _log;
        byte[] AESkey;
        const int AESkeyLen = 16;

        byte[] salt;
        //int saltLen; //== tokenLen

        /* Note: this structure is suitable with received packet, when we don't get length file (4B) to Tcpbuff
         * So be carefully use this with send packet
         */
        struct TcpPacketStruct
        {
            public const int POS_OF_LEN = 0;
            public const int SIZE_OF_LEN = 2; //2B len of packet, //16B MD5
            public const int POS_OF_MD5 = 2; //right after len filed
            public const int SIZE_OF_MD5 = 16;
            public const int POS_OF_PAYLOAD = 18; //position of payload of packet

            public const int SIZE_OF_PUBKEY = 256; //bytes

            public const int HEADER_LEN = SIZE_OF_LEN + SIZE_OF_MD5;
        }
        //** param need config
        internal string token { get; private set; } //~ID of device
        int tokenLen;
        int TCP_BUFF_LEN_MAX = 10000;

        byte[] Tcpbuff;
        int TcpbuffOffset = 0;

        bool bIsPending = false;
        int remainData = 0;   //reamin data need to collect
        int curPacketSize;
        bool ErrorRecv = false;

        

        //** virtual methods, need to override
        //derived can use to do something when client TLS handshake is successful, like add to list
        protected virtual void OnTLSConnectedNotify()
        {

        }

        //derived can use to do something when client disconnected, like remove from list
        protected virtual void OnTLSDisConnectedNotify()
        {

        }

        class MP3PacketHeader
        {
            public const int AESkeyLen = 16;

            public const int SIZE_OF_LEN = 2;
            //static UINT16 len;
            public const int POS_OF_LEN = 0;

            //16B MD5
            public const int POS_OF_MD5 = 2;

            //static byte type;
            public const int POS_OF_TYPE = 2 + 16;

            //static UInt32 session;
            public const int POS_OF_SESSION = 2 + 16 + 1;
            public const int SESSION_LEN = 4; //4B

            //16B AES_key-128
            public const int POS_OF_AESKEY = 2 + 16 + 1 + 4;

            //static byte volume;
            public const int POS_OF_VOLUME = 2 + 16 + 1 + 4 + 16;

            //static long timestamp;
            static int timestamp_offset = 2 + 16 + 1 + 4 + 16 + 1;

            //static UInt32 frameID;
            static int frameID_offset = 2 + 16 + 1 + 4 + 16 + 1 + 8;

            //static byte numOfFrame; //1B
            static int numOfFrame_offset = 2 + 16 + 1 + 4 + 16 + 1 + 8 + 4;

            //static UInt16 sizeOfFirstFrame; //2B
            static int sizeOfFirstFrame_offset = 2 + 16 + 1 + 4 + 16 + 1 + 8 + 4 + 1;

            //static UInt16 frameSize; //2B
            static int frameSize_offset = 2 + 16 + 1 + 4 + 16 + 1 + 8 + 4 + 1 + 2;

            //static byte timePerFrame; //1B (ms)
            static int timePerFrame_offset = 2 + 16 + 1 + 4 + 16 + 1 + 8 + 4 + 1 + 2 + 2;

            public const int HEADER_SIZE = 4 + 16 + 1 + 4 + 16 + 1 + 8 + 4 + 1 + 2 + 2 + 1;
        }

        //handle TLS packet (after TLS handshake) at derived class, return false ~ error
        // 1, 2, 3, 4
        internal enum RecvPackeTypeEnum { Status, PacketAudio };
        protected virtual bool HandleTLSPacket()
        {
            bool error = true;
            //decrypt first block to get type
            byte[] decrypt = AES.AES_Decrypt(Tcpbuff, TcpPacketStruct.POS_OF_PAYLOAD, AES.AES_BLOCK_LEN, AESkey, true);
            if(decrypt != null)
            {
                //get type of packet
                if(Tcpbuff[TcpPacketStruct.POS_OF_PAYLOAD] == (byte)RecvPackeTypeEnum.PacketAudio)
                {
                    UInt32 session = BitConverter.ToUInt32(Tcpbuff, MP3PacketHeader.POS_OF_SESSION);

                    //decrypt next block to get AES key
                    decrypt = AES.AES_Decrypt(Tcpbuff, MP3PacketHeader.POS_OF_TYPE + AES.AES_BLOCK_LEN, AES.AES_BLOCK_LEN, AESkey, true);
                    byte[] tmpAESkey = new byte[AESkeyLen];
                    System.Buffer.BlockCopy(Tcpbuff, MP3PacketHeader.POS_OF_AESKEY, tmpAESkey, 0, AESkeyLen);

                    //decrypt data after volume
                    int tmpLen = curPacketSize + MP3PacketHeader.SIZE_OF_LEN - MP3PacketHeader.POS_OF_VOLUME;
                    decrypt = AES.AES_Decrypt_NoPadding(Tcpbuff, MP3PacketHeader.POS_OF_VOLUME, tmpLen, tmpAESkey, true);
                    if(decrypt != null && Tcpbuff[curPacketSize + 1] == 'y' && Tcpbuff[MP3PacketHeader.POS_OF_VOLUME] == 100) //debug
                    {
                        Console.Write(".");
                        error = false;
                    }
                }
                else if (Tcpbuff[TcpPacketStruct.POS_OF_PAYLOAD] == (byte)RecvPackeTypeEnum.Status)
                {
                    error = false;
                }
            }
            return !error;
        }

        public TLSClient(string address, int port, ILogger<TLSClient> log) : base(address, port)
        {
            IsHandshaked = false;
            _log = log;

            InitiliazeTimeoutTimer();
        }

        public void ConfigParam(string _token, int _tcpBuffMaxLen)
        {
            token = _token;
            tokenLen = token.Length;
            TCP_BUFF_LEN_MAX = _tcpBuffMaxLen;
        }

        void InitiliazeTimeoutTimer()
        {
            // Create a timer to handle connect time-out
            timer = new System.Timers.Timer(CONNECT_TIMEOUT);
            // Hook up the Elapsed event for the timer. 
            timer.Elapsed += TimerEvent;
            timer.AutoReset = true;
            timer.Enabled = true;
        }

        //when we send anything else, we will reset time point need to keep alive
        void ResetKeepAliveTimer()
        {
            timer.Interval = KEEP_ALIVE_INTERVAL;
        }

        //2 case: 1.time-out when TLS handshake still not success, 2.when TLS is successful and we need to send keep alive
        private void TimerEvent(Object source, ElapsedEventArgs e)
        {
            if(!IsHandshaked)
            {
                _log.LogInformation($"{Id} timeout.");
                Disconnect();
            }
            else
            {
                //send keep alive packet
                byte[] kaBuff = new byte[5];
                kaBuff[0] = 1;
                SendAsync(kaBuff);
            }
        }

        protected override void OnConnected()
        {
            //ConnectedTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            _log.LogInformation($"{Id} connected!");

            //send keep alive packet to request rsa-pubkey
            byte[] kaBuff = new byte[3];
            kaBuff[0] = 1;
            SendAsync(kaBuff);

            //initialize Tcp buff
            Tcpbuff = new byte[TCP_BUFF_LEN_MAX];
        }

        protected override void OnDisconnected()
        {
            _log.LogError($"{Id} disconnected!");

            OnTLSDisConnectedNotify();

            Thread.Sleep(2000);

            //reset before re-connect
            IsHandshaked = false;
            TcpbuffOffset = 0;
            bIsPending = false;
            remainData = 0;   //reamin data need to collect
            curPacketSize = 0;
            ErrorRecv = false;
            connectStatus = 0;

            //ConnectAsync(); //re-connect
        }

        int connectStatus = 0; //0: need pubkey, 1: need ACK, 2:successful TLS handshake
        //first we wil store length filed (4B) to read len of packet

        public void AnalyzeRecvTcpPacketString(byte[] recvData, int offset, int length)
        {
            int upper = length + offset;
            while(length > 0)
            {
                int eofPackIndx = -1;

                for (int i = offset; i < upper; i++)
                {
                    if (recvData[i] == '#')
                    {
                        eofPackIndx = i;
                        break;
                    }
                }

                if (eofPackIndx == -1) //not find "#"
                {
                    if(TcpbuffOffset + length < TCP_BUFF_LEN_MAX)
                    {
                        System.Buffer.BlockCopy(recvData, offset, Tcpbuff, TcpbuffOffset, length);
                        TcpbuffOffset += length;
                        length = 0;
                    }
                }
                else
                {
                    int lenTmp = eofPackIndx - offset; // 0 1 2 3 4
                    if(lenTmp > 0 && TcpbuffOffset + lenTmp < TCP_BUFF_LEN_MAX)
                    {
                        System.Buffer.BlockCopy(recvData, offset, Tcpbuff, TcpbuffOffset, lenTmp);
                        TcpbuffOffset += lenTmp;
                    }
                    offset = eofPackIndx + 1; //+1 for "#"
                    length -= (lenTmp + 1); // +1 for "#"

                    //handle tcp packet
                    if (TcpbuffOffset % 2 == 0) //byte to hex string -> double length of packet
                    {
                        //convert string to hex
                        //TcpbuffOffset ~ length of Tcp packet
                        Tcpbuff[TcpbuffOffset] = 0;
                        //convert byte[] to string
                        string tcpPacketStrTmp = Encoding.ASCII.GetString(Tcpbuff, 0, TcpbuffOffset);
                        byte[] tcpPacketByteTmp = Convert.FromHexString(tcpPacketStrTmp);

                        //check length field
                        int lenOfPacket = (int)BitConverter.ToUInt16(tcpPacketByteTmp, 0);
                        if(lenOfPacket == tcpPacketByteTmp.Length - 2) //2 byte of length field
                        {
                            curPacketSize = lenOfPacket;
                            //copy to Tcpbuff (include len field)
                            System.Buffer.BlockCopy(tcpPacketByteTmp, 0, Tcpbuff, 0, tcpPacketByteTmp.Length);
                            HandleRecvTcpPacket();
                        }
                    }

                    TcpbuffOffset = 0;
                }
            }
        }

        bool CheckMD5()
        {
            //check AES
            if (connectStatus == 0) //it is first packet pubkey, not necessary decrypt MD5
            {

            }
            else
            {
                //decrypt MD5 first
                byte[] MD5checksum = AES.AES_Decrypt(Tcpbuff, TcpPacketStruct.POS_OF_MD5, TcpPacketStruct.SIZE_OF_MD5, AESkey, true); //overwrite
                if (MD5checksum == null) return false;
            }

            byte[] hashed = MD5.MD5Hash(Tcpbuff, TcpPacketStruct.POS_OF_PAYLOAD, curPacketSize - TcpPacketStruct.SIZE_OF_MD5);
            //CompareMD5 (16B)
            for (int i = 0; i < TcpPacketStruct.SIZE_OF_MD5; i++)
            {
                if (hashed[i] != Tcpbuff[TcpPacketStruct.POS_OF_MD5 + i]) return false;
            }
            return true;
        }

        enum SaltEnum { Add, Sub};
        void ConvertTextWithSalt(byte[] data, int offset, int len, SaltEnum saltType)
        {
            if (salt == null) return; //something wrong ???

            int i = 0, j = 0;
            if(saltType == SaltEnum.Add)
            {
                while (j < len)
                {
                    data[j + offset] += salt[i];
                    j++;
                    i++;
                    if (i == salt.Length) i = 0;
                }
            }
            else //sub
            {
                while (j < len)
                {
                    data[j + offset] -= salt[i];
                    byte tmp = data[j + offset];
                    j++;
                    i++;
                    if (i == salt.Length) i = 0;
                }
            }
        }
        bool CheckSaltACK(byte[] data, int offset, int len)
        {
            if(len >= salt.Length)
            {
                for(int i = 0; i < salt.Length; i++)
                {
                    if ((data[i + offset] & 0x7F) != salt[i]) return false;
                }
                return true;
            }
            return false;
        }
        void HandleRecvTcpPacket()
        {
            ErrorRecv = true;
            //at least 16B MD5, 1B data / payload
            if (curPacketSize > TcpPacketStruct.SIZE_OF_MD5)
            {
                //check MD5 first
                if (CheckMD5())
                {
                    if (IsHandshaked)
                    {
                        if (HandleTLSPacket())  //handle at derived class
                            ErrorRecv = false;
                    }
                    else
                    {
                        if (connectStatus == 0 && curPacketSize == (TcpPacketStruct.SIZE_OF_MD5 + TcpPacketStruct.SIZE_OF_PUBKEY)) //pubkey packet,  //check length of packet
                        {
                            //get pubkey
                            byte[] pubKey = new byte[TcpPacketStruct.SIZE_OF_PUBKEY];
                            System.Buffer.BlockCopy(Tcpbuff, TcpPacketStruct.POS_OF_PAYLOAD, pubKey, 0, TcpPacketStruct.SIZE_OF_PUBKEY);
                            byte[] expponent = { 1, 0, 1 };

                            //send MD5, salt, token, AES_key
                            AESkey = new byte[AESkeyLen];
                            Random rd = new Random();
                            rd.NextBytes(AESkey);
                            byte[] sendBuff = new byte[TcpPacketStruct.HEADER_LEN + tokenLen + tokenLen + AESkeyLen];
                            rd.NextBytes(sendBuff);

                            //copy token to send buff
                            System.Buffer.BlockCopy(Encoding.UTF8.GetBytes(token), 0, sendBuff, TcpPacketStruct.POS_OF_PAYLOAD + tokenLen, tokenLen);

                            salt = new byte[tokenLen];
                            rd.NextBytes(salt);
                            //copy salt to send buff
                            System.Buffer.BlockCopy(salt, 0, sendBuff, TcpPacketStruct.POS_OF_PAYLOAD, tokenLen);
                            for (int i = 0; i < tokenLen; i++) { salt[i] &= 0x7F; } //convert salt to standard form
                            ConvertTextWithSalt(sendBuff, TcpPacketStruct.POS_OF_PAYLOAD + tokenLen, tokenLen, SaltEnum.Add);

                            //copy AES
                            System.Buffer.BlockCopy(AESkey, 0, sendBuff, TcpPacketStruct.POS_OF_PAYLOAD + tokenLen + tokenLen, AESkeyLen);

                            //caculate MD5
                            byte[] md5sum = MD5.MD5Hash(sendBuff, TcpPacketStruct.POS_OF_PAYLOAD, tokenLen + tokenLen + AESkeyLen);
                            System.Buffer.BlockCopy(md5sum, 0, sendBuff, TcpPacketStruct.POS_OF_MD5, md5sum.Length);

                            //encrypt RSA
                            byte[] rsaBuff = new byte[sendBuff.Length - TcpPacketStruct.SIZE_OF_LEN];
                            System.Buffer.BlockCopy(sendBuff, TcpPacketStruct.POS_OF_MD5, rsaBuff, 0, rsaBuff.Length);

                            byte[] encrypted = RSA.Encrypt(rsaBuff, pubKey, expponent);
                            if (encrypted != null)
                            {
                                sendBuff = new byte[encrypted.Length + TcpPacketStruct.SIZE_OF_LEN];
                                System.Buffer.BlockCopy(encrypted, 0, sendBuff, TcpPacketStruct.POS_OF_MD5, encrypted.Length);
                                //copy len field
                                System.Buffer.BlockCopy(BitConverter.GetBytes((UInt16)encrypted.Length), 0, sendBuff, TcpPacketStruct.POS_OF_LEN, 2);

                                SendAsync(sendBuff);
                                connectStatus = 1;
                                ErrorRecv = false;
                            }
                        }
                        else if (connectStatus == 1) //ack packet
                        {
                            byte[] output = AES.AES_Decrypt_NoPadding(Tcpbuff, TcpPacketStruct.POS_OF_PAYLOAD, curPacketSize - TcpPacketStruct.SIZE_OF_MD5, AESkey, true);
                            if(output != null)
                            {
                                //check salt
                                if(CheckSaltACK(Tcpbuff, TcpPacketStruct.POS_OF_PAYLOAD, curPacketSize - TcpPacketStruct.SIZE_OF_MD5))
                                {
                                    ErrorRecv = false;
                                    IsHandshaked = true;
                                    connectStatus = 2;
                                    ResetKeepAliveTimer();
                                }
                            }
                        }
                    }
                }
            } 
            
            
            if (ErrorRecv)
            {
                Disconnect();
            }
            else
            {
                //ResetTimeoutTimer();
                ////record recv time to database
                //ConnectedTime = DateTimeOffset.Now.ToUnixTimeSeconds();
                //RecordTimeConnectedToDatabase();
            }
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            //string message = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            //Console.WriteLine("Incoming: " + message);
            //_log.LogInformation($"{Id} Recv_len: {size}");

            AnalyzeRecvTcpPacketString(buffer, (int)offset, (int)size);
        }

        protected override void OnError(SocketError error)
        {
            _log.LogError($"Chat TCP session caught an error with code {error}");
        }

        protected override void OnEmpty()
        {
            //Console.WriteLine($"ID {Id}, Pending byte: {BytesPending}, Sending bytes: {BytesSending}, Sent bytes: {BytesSent}");
        }

        //1 2 3 4 5
        internal enum SendPackeTypeEnum { Status, PacketAudio };

        //get length and add MD5 (then encrypt) to packet before send
        internal void SendPacketAsync(byte[] data, int offset, int len)
        {
            //check data array
            if ((data.Length - offset) < len) return;

            byte[] headerArr = new byte[TcpPacketStruct.HEADER_LEN];
            System.Buffer.BlockCopy(BitConverter.GetBytes(TcpPacketStruct.SIZE_OF_MD5 + len), 0, headerArr, 0, sizeof(int));
            if(AESkey != null)
            {
                byte[] md5Checksum = MD5.MD5Hash(data, offset, len);
                md5Checksum = AES.AES_Encrypt(md5Checksum, 0, md5Checksum.Length, AESkey); //encrypt
                System.Buffer.BlockCopy(md5Checksum, 0, headerArr, sizeof(int), TcpPacketStruct.SIZE_OF_MD5);

                //encrypt data
                byte[] encryptedData = AES.AES_Encrypt(data, offset, len, AESkey);

                //send header then payload
                SendAsync(headerArr);
                SendAsync(encryptedData);
            }
            else //this case has only one packet, that is sending pubkey
            {
                byte[] md5Checksum = MD5.MD5Hash(data, offset, len);
                System.Buffer.BlockCopy(md5Checksum, 0, headerArr, sizeof(int), TcpPacketStruct.SIZE_OF_MD5);
                SendAsync(headerArr);
                SendAsync(data, (long)offset, (long)len);
            }
        }

        void SendHandshakePackAsync(byte[] data, int offset, int len)
        {
            if (!IsHandshaked)
            {
                SendAsync(BitConverter.GetBytes((UInt16)len));
                SendAsync(data, offset, len);
            }
        }

    }
}
