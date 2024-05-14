using System.Security.Cryptography;
using System.Text;

namespace Utils.Cyrpto
{
    public static class CyrptoExtention
    {
        /// <summary>
        /// Verilen değerin MD5 özetini alır.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string Md5Encrypt(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                string val = string.Empty;
                MD5CryptoServiceProvider md5Cyripto = new MD5CryptoServiceProvider();
                byte[] bytes = Encoding.ASCII.GetBytes(value);
                byte[] arrays = md5Cyripto.ComputeHash(bytes);
                int capacity = (int)Math.Round(arrays.Length * 3 + (double)arrays.Length / 8);
                StringBuilder builder = new StringBuilder(capacity);
                int num = arrays.Length - 1;
                for (int i = 0; i <= num; i++)
                {
                    builder.Append(BitConverter.ToString(arrays, i, 1));
                }
                val = builder.ToString().TrimEnd(new char[] { ' ' });
                return val;
            }
            return null;
        }

        public static string EncryptAes(this string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        byte[] cipherBytes = msEncrypt.ToArray();
                        string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);
                        return cipherText;
                    }
                }

            }
        }

        public static string DecryptAes(this string cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        string plainText = string.Empty;
                        byte[] cipherBytes = Convert.FromBase64String(cipherText);
                        csDecrypt.Write(cipherBytes, 0, cipherBytes.Length);
                        csDecrypt.FlushFinalBlock();
                        byte[] plainBytes = msDecrypt.ToArray();
                        plainText = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
                        return plainText;
                    }
                }
            }
        }

    }
    public sealed class HashingManager
    {
        #region Singleton Section
        private static readonly Lazy<HashingManager> _instance = new Lazy<HashingManager>(() => new HashingManager());

        private HashingManager()
        {
        }

        public static HashingManager Instance => _instance.Value;
        #endregion

        internal byte[] SaltAsByte => new byte[16];

        private string defaultEncryptionKey = "CFEF4D7105714597B7FB0E59BA5B3464";

        public string EncryptAesAsString(string dataToEncrypt, string encryptionKey)
        {
            var newEncryptionKey = defaultEncryptionKey.Remove(defaultEncryptionKey.Length - encryptionKey.Length);
            newEncryptionKey += encryptionKey;
            return dataToEncrypt.EncryptAes(Encoding.UTF8.GetBytes(newEncryptionKey), SaltAsByte);
        }

        public string DecryptFromAesAsString(string data, string encryptionKey)
        {
            try
            {
                var newEncryptionKey = defaultEncryptionKey.Remove(defaultEncryptionKey.Length - encryptionKey.Length);
                newEncryptionKey += encryptionKey;

                return data.DecryptAes(Encoding.UTF8.GetBytes(newEncryptionKey), SaltAsByte);
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        public string EncryptDefaultAesAsString(string dataToEncrypt)
        {
            return dataToEncrypt.EncryptAes(Encoding.UTF8.GetBytes(defaultEncryptionKey), SaltAsByte);
        }

        public string DecryptDefaultFromAesAsString(string data)
        {
            return data.DecryptAes(Encoding.UTF8.GetBytes(defaultEncryptionKey), SaltAsByte);
        }

        public static void Main(string[] args)
        {
            var mail = "Eyyüp@gmail.com";
            var password = "162539";


            var encryptPassword = HashingManager.Instance.EncryptAesAsString(password, "Password");
            Console.WriteLine(encryptPassword);

            var decryptPassword = HashingManager.Instance.DecryptFromAesAsString(encryptPassword, "Password");
            Console.WriteLine(decryptPassword);

        }
    }
}



