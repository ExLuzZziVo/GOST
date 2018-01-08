using GOST.Interfaces;
using GOST.SBlocks;
using GOST.Types;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("GOSTTests")]

namespace GOST.Ciphers
{
    internal class SubstitutionCipher : ISubstitutionCipher
    {
        private ISBlocks sBlock;

        public SubstitutionCipher(ISBlocks sBlock)
        {
            this.sBlock = sBlock;
        }

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">64-х битный блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            var little = BitConverter.ToUInt32(data, 0);
            var big = BitConverter.ToUInt32(data, 4);

            for (int i = 0; i != 32; i++)
            {
                var round = big ^ Function(little, subKeys[GetSubKeyIndex(i, true)]);

                if (i < 31)
                {
                    big = little;
                    little = round;
                }
                else
                {
                    big = round;
                }
            }

            var result = BitConverter.GetBytes(uint.Parse(little.ToString() + big.ToString()));
            return result;
        }

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">64-х битный блок шифротекста.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Получение индекса субключа.
        /// </summary>
        /// <param name="iteration">Текущая итерация шифрования блока.</param>
        /// <param name="encrypt">Шифрование/Дешифрование.</param>
        /// <returns>Индекс субключа.</returns>
        public int GetSubKeyIndex(int iteration, bool encrypt)
        {
            // TODO: Переписать надо бы. Думаю не выбирать отсюда процесс инвертирования, а инвертировать сам лист с подключами до шифрования.
            return encrypt ? (iteration < 24) ? iteration % 8 : 7 - (iteration % 8)
                   : (iteration < 8) ? iteration % 8 : 7 - (iteration % 8);
        }

        /// <summary>
        /// Основная функция шифрования.
        /// </summary>
        /// <param name="block">Младшие биты.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>Результат шифрования функцией.</returns>
        public uint Function(uint block, uint subKey)
        {
            block = (block + subKey) % 4294967295;
            block = Substitute(block);
            block = (block << 11) | (block >> 21);
            return block;
        }

        /// <summary>
        /// Подстановка.
        /// </summary>
        /// <param name="block">Блок для подстановки.</param>
        /// <returns>Блок после подстановки.</returns>
        public uint Substitute(uint value)
        {
            uint res = 0;

            for (int i = 0; i != 8; i++)
            {
                byte index = (byte)(value >> (4 * i) & 0x0f);
                byte block = sBlock.SBlockTable[i][index];
                res |= (uint)block << (4 * i);
            }

            return res;
        }
    }
}
