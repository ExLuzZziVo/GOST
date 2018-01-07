using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Types
{
    // Подстановка, гаммирование, гаммирование с обратной связью, иммитовставка.
    public enum CipherTypes
    {
        Substitution, XOR, ReverseXOR, MAC
    }

    public enum SBlockTypes
    {
        GOST, CryptoProA, CryptoProB, CryptoProC, CryptoProD, TC26
    }
}
