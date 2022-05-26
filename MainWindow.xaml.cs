using System;
using System.Collections.Generic;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace PasswordGenerator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static string DefaultPunctuations = "!@#$%^&*()_-+=;:|./?[{]}`~";
        public static int MaximumLength = 50;

        public MainWindow()
        {
            InitializeComponent();
            txtPunctuationsAllowed.Text = DefaultPunctuations;
        }

        // From System.Web  Security\Membership.cs GeneratePassword
        private static string GeneratePassword(int length, int minimumPunctuationCharacters, int maximumPunctuationCharacters, string punctuationsAllowed,
            bool mustHaveUpper, bool mustHaveLower, bool mustHaveDigit)
        {
            if (length < 1 || length > 128)
            {
                throw new ArgumentException("Password length is incorrect", nameof(length));
            }

            if (minimumPunctuationCharacters > length || minimumPunctuationCharacters < 0)
            {
                throw new ArgumentException("Minimum number of non-alphanumeric characters is incorrect", nameof(minimumPunctuationCharacters));
            }

            if (maximumPunctuationCharacters > length || maximumPunctuationCharacters < 0)
            {
                throw new ArgumentException("Maximum number of non-alphanumeric characters is incorrect", nameof(maximumPunctuationCharacters));
            }

            var punctuations = punctuationsAllowed.ToCharArray();
            // 62 is 52 upper and lower alpha plus digits 0 to 9
            int characterRange = 62 + punctuations.Length;

            string password;
            int index;
            byte[] buf;
            char[] cBuf;
            int upperCount;
            int lowerCount;
            int digitCount;
            int punctuationCount;

            Random rand = new Random();

            do
            {
                buf = new byte[length];
                cBuf = new char[length];
                upperCount = 0;
                lowerCount = 0;
                digitCount = 0;
                punctuationCount = 0;

                (new RNGCryptoServiceProvider()).GetBytes(buf);

                for (int iter = 0; iter < length; iter++)
                {
                    int i = (int)(buf[iter] % characterRange);
                    if (i < 10)
                    {
                        cBuf[iter] = (char)('0' + i);
                        digitCount++;
                    }
                    else if (i < 36)
                    {
                        cBuf[iter] = (char)('A' + i - 10);
                        upperCount++;
                    }
                    else if (i < 62)
                    {
                        cBuf[iter] = (char)('a' + i - 36);
                        lowerCount++;
                    }
                    else
                    {
                        cBuf[iter] = punctuations[i - 62];
                        punctuationCount++;
                    }
                }

                HashSet<int> availablePositions = new HashSet<int>(Enumerable.Range(0, length));
                if (punctuationCount < minimumPunctuationCharacters)
                {
                    int j, k;

                    for (j = 0; j < minimumPunctuationCharacters - punctuationCount && availablePositions.Any(); j++)
                    {
                        do
                        {
                            var available = availablePositions.ToArray();
                            k = available[rand.Next(0, available.Length)];
                        }
                        while (!Char.IsLetterOrDigit(cBuf[k]));

                        cBuf[k] = punctuations[rand.Next(0, punctuations.Length)];
                        availablePositions.Remove(k);
                        punctuationCount++;
                    }
                }

                while (length > 3 && 
                    availablePositions.Count > 3 &&
                    ((mustHaveUpper && upperCount == 0) || 
                     (mustHaveLower && lowerCount == 0) || 
                     (mustHaveDigit && digitCount == 0) || 
                     punctuationCount > maximumPunctuationCharacters) 
                    )
                {
                    int upperCharactersToAdd = (mustHaveUpper && upperCount == 0 || punctuationCount > maximumPunctuationCharacters) ? rand.Next(1, Math.Min(length, 3)) : 0;
                    int lowerCharactersToAdd = (mustHaveLower && lowerCount == 0 || punctuationCount > maximumPunctuationCharacters) ? rand.Next(1, Math.Min(length, 3)) : 0;
                    int digitCharactersToAdd = (mustHaveDigit && digitCount == 0 || punctuationCount > maximumPunctuationCharacters) ? rand.Next(1, Math.Min(length, 3)) : 0;
                    if (upperCharactersToAdd + lowerCharactersToAdd + digitCharactersToAdd > availablePositions.Count)
                    {
                        upperCharactersToAdd = (mustHaveUpper && upperCount == 0 || punctuationCount > maximumPunctuationCharacters) ? 1 : 0;
                        lowerCharactersToAdd = (mustHaveLower && lowerCount == 0 || punctuationCount > maximumPunctuationCharacters) ? 1 : 0;
                        digitCharactersToAdd = (mustHaveDigit && digitCount == 0 || punctuationCount > maximumPunctuationCharacters) ? 1 : 0;
                    }

                    int k;
                    for (int j = 0; j < upperCharactersToAdd && availablePositions.Any(); j++)
                    {
                        var available = availablePositions.ToArray();
                        k = available[rand.Next(0, available.Length)];

                        var originalChar = cBuf[k];
                        cBuf[k] = (char)('A' + rand.Next(0, 26));
                        availablePositions.Remove(k);
                        upperCount++;
                        if (!Char.IsLetterOrDigit(originalChar))
                        {
                            punctuationCount--;
                        }
                    }

                    for (int j = 0; j < lowerCharactersToAdd && availablePositions.Any(); j++)
                    {
                        var available = availablePositions.ToArray();
                        k = available[rand.Next(0, available.Length)];

                        var originalChar = cBuf[k];
                        cBuf[k] = (char)('a' + rand.Next(0, 26));
                        availablePositions.Remove(k);
                        lowerCount++;
                        if (!Char.IsLetterOrDigit(originalChar))
                        {
                            punctuationCount--;
                        }
                    }

                    for (int j = 0; j < digitCharactersToAdd && availablePositions.Any(); j++)
                    {
                        var available = availablePositions.ToArray();
                        k = available[rand.Next(0, available.Length)];

                        var originalChar = cBuf[k];
                        cBuf[k] = (char)('0' + rand.Next(0, 10));
                        availablePositions.Remove(k);
                        digitCount++;
                        if (!Char.IsLetterOrDigit(originalChar))
                        {
                            punctuationCount--;
                        }
                    }
                }

                password = new string(cBuf);
            }
            while (IsDangerousString(password, out index));

            return password;
        }

        private static char[] startingChars = new char[] { '&' };

        internal static bool IsDangerousString(string s, out int matchIndex)
        {
            //bool inComment = false;
            matchIndex = 0;

            for (int i = 0; ;)
            {

                // Look for the start of one of our patterns
                int n = s.IndexOfAny(startingChars, i);

                // If not found, the string is safe
                if (n < 0) return false;

                // If it's the last char, it's safe
                if (n == s.Length - 1) return false;

                matchIndex = n;

                switch (s[n])
                {
                    //case '<':
                    //    // If the < is followed by a letter or '!', it's unsafe (looks like a tag or HTML comment)
                    //    if (IsAtoZ(s[n + 1]) || s[n + 1] == '!' || s[n + 1] == '/' || s[n + 1] == '?') return true;
                    //    break;
                    case '&':
                        // If the & is followed by a #, it's unsafe (e.g. &#83;)
                        if (s[n + 1] == '#') return true;
                        break;
                }

                // Continue searching
                i = n + 1;
            }
        }

        private void btnGenerate_Click(object sender, RoutedEventArgs e)
        {
            string message = string.Empty;

            bool mustHaveUpper = chkMustHaveUpper.IsChecked ?? false;
            bool mustHaveLower = chkMustHaveLower.IsChecked ?? false;
            bool mustHaveDigit = chkMustHaveDigit.IsChecked ?? false;

            if (!int.TryParse(txtMinimum.Text, out int minimumCharacters))
            {
                message = "Minimum characters must be numeric";
            }
            else if (minimumCharacters < 1 || minimumCharacters > MaximumLength)
            {
                message = "Minimum characters is out of range";
            }

            if (!int.TryParse(txtMaximum.Text, out int maximumCharacters))
            {
                message = "Maximum characters must be numeric";
            }
            else if (maximumCharacters < 1 || maximumCharacters > MaximumLength || maximumCharacters < minimumCharacters)
            {
                message = "Maximum characters is out of range";
            }

            if (!int.TryParse(txtMinimumPunctuation.Text, out int minimumPunctuations))
            {
                message = "Minimum punctuation characters must be numeric";
            }
            else if (minimumPunctuations < 0 || minimumPunctuations > maximumCharacters)
            {
                message = "Minimum punctuation characters is out of range";
            }

            if (!int.TryParse(txtMaximumPunctuation.Text, out int maximumPunctuations))
            {
                message = "Maximum punctuation characters must be numeric";
            }
            else if (maximumPunctuations < 0 || minimumPunctuations > maximumPunctuations || maximumPunctuations > maximumCharacters)
            {
                message = "Maximum punctuation characters is out of range";
            }

            string punctuationsAllowed = (maximumPunctuations > 0) ? txtPunctuationsAllowed.Text : string.Empty;
            HashSet<Char> includedPunctuations = new HashSet<Char>();
            foreach (char ch in punctuationsAllowed)
            {
                if (Char.IsControl(ch) ||
                    Char.IsWhiteSpace(ch) ||
                    Char.IsLetterOrDigit(ch) || 
                    ch == '<' || 
                    ch == '>' || 
                    ch == ' ' || 
                    !DefaultPunctuations.Contains(ch))
                {
                    message = $"Invalid punctuation mark added - {ch} ({(int)ch})";
                    break;
                }

                if (includedPunctuations.Contains(ch))
                {
                    message = $"Punctuation included multiple times - {ch} ({(int)ch})";
                    break;
                }
                includedPunctuations.Add(ch);
            }

            if (!string.IsNullOrEmpty(message))
            {
                MessageBox.Show(message);
                txtPassword.Text = string.Empty;
            }
            else
            {
                var random = new System.Random();
                int length = random.Next(minimumCharacters, maximumCharacters);

                try
                {
                    txtPassword.Text = GeneratePassword(length: length,
                        minimumPunctuationCharacters: minimumPunctuations,
                        maximumPunctuationCharacters: Math.Min(maximumPunctuations, length),
                        punctuationsAllowed: punctuationsAllowed,
                        mustHaveUpper: mustHaveUpper,
                        mustHaveLower: mustHaveLower,
                        mustHaveDigit: mustHaveDigit);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    txtPassword.Text = string.Empty;
                }
            }
        }

        private void btnCopy_Click(object sender, RoutedEventArgs e)
        {
            string password = txtPassword.Text;
            System.Windows.Clipboard.SetDataObject(password);
        }
    }
}
