using GOST.Interfaces;
using GOST.Types;
using System;

namespace GOST.Managers
{
    public class GOSTManaged : IManager
    {
        private ICipher cipher;
        private CipherTypes type;
        // 256 битный ключ.
        private byte[] key;
        // Сообщение.
        private byte[] message;

        public byte[] Key
        {
            get { return key; }
            set
            {
                if (value.Length > 32)
                {
                    throw new ArgumentException("Key Overflow. Try to use 256 bit key.");
                }
                else if (value.Length == 32)
                {
                    key = value;
                }
                else
                {
                    key = value;
                    for (int i = value.Length; i != 32; i++)
                    {
                        var newKey = new byte[key.Length + 1];
                        key.CopyTo(newKey, 0);
                        newKey[newKey.Length-1] = 0;
                        key = newKey;
                    }
                }
            }
        }

        public byte[] Message
        {
            get { return message; }
            set
            {
                if (value == null || value.Length == 0)
                {
                    throw new ArgumentException("Empty message!");
                }
                else
                {
                    message = value;
                }
            }
        }

        public GOSTManaged(byte[] key, byte[] message, CipherTypes type)
        {
            Key = key;
            Message = message;
            this.type = type;
        }

        public byte[] Encode()
        {
            throw new NotImplementedException();
        }
    }
}