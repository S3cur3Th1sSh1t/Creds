using System;
using System.IO;

namespace MonkeyWorks
{
    sealed class Combine
    {
        private Byte[] combined = new Byte[0];

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public Combine()
        {

        }

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        internal static Byte[] combine(Byte[] byte1, Byte[] byte2)
        {
            Int32 dwSize = byte1.Length + byte2.Length;
            Byte[] combinedBytes = new Byte[0];
            using (MemoryStream memoryStream = new MemoryStream(new Byte[dwSize], 0, dwSize, true, true))
            {
                memoryStream.Write(byte1, 0, byte1.Length);
                memoryStream.Write(byte2, 0, byte2.Length);
                combinedBytes = memoryStream.GetBuffer();
            }
            return combinedBytes;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public void Extend(Byte[] nextPart)
        {
            Int32 dwSize = combined.Length + nextPart.Length;
            using (MemoryStream memoryStream = new MemoryStream(new Byte[dwSize], 0, dwSize, true, true))
            {
                memoryStream.Write(combined, 0, combined.Length);
                memoryStream.Write(nextPart, 0, nextPart.Length);
                combined = memoryStream.GetBuffer();
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // 
        ////////////////////////////////////////////////////////////////////////////////
        public Byte[] Retrieve()
        {
            return combined;
        }
    }
}
