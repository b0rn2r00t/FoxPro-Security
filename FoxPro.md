**NULL Attack Surface:**

- Conditionals with NULL(almost) always return false

A **NULL attack surface** is a type of security vulnerability that occurs when a conditional statement does not properly handle NULL values. This can allow attackers to inject malicious code into the application.

**Conditionals with NULL(almost) always return f** means that if one of the operands of a conditional statement is NULL, the conditional statement will almost always evaluate to false. This is because most programming languages interpret NULL as a false value.

Here is an example of a conditional statement in Visual FoxPro that is vulnerable to a NULL attack surface:

```php
IF my_variable IS NULL THEN
    DO THIS
ELSE
    DO SOMETHING ELSE
ENDIF
```

```visual-basic
* ASSUME: We located the correct record in USER.DBF
IF NOT ALLTRIM(User.cPassword) == m.lcPassword
  * invalid password
ELSE
  * password is OK
ENDIF
```

If the value of `my_variable` is NULL, the conditional statement will evaluate to false and the code in the `ELSE` block will be executed. This means that an attacker can inject malicious code into the application by setting the value of `my_variable` to NULL.

Here is an example of how to fix the conditional statement:

```visual-basic
IF NOT(my_variable IS NULL) THEN
    DO THIS
ELSE
    DO SOMETHING ELSE
ENDIF
```

To prevent NULL attack surfaces in Visual FoxPro, you should follow these best practices:

- Use the `NOT()` function to check if a value is not NULL.
- Use prepared statements when executing SQL queries.
- Avoid using conditional statements that rely on the implicit conversion of NULL to false.
- Keep your Visual FoxPro software up to date.

If two strings are considered to be equal depends on a number of factors. These are SET EXACT, SET NEAR, SET COLLATE, SET ANSI, as well as various codepage related settings. Take a look at the following sample and find out how to bypass the validation routine:

```visual-basic
* ASSUME: We located the correct record in USER.DBF
lcPassword = NVL(m.lcPassword,"")       //live and learn...
IF ALLTRIM(User.cPassword) = m.lcPassword
  * invalid password
ELSE
  * password is OK
ENDIF
```

Instead of using the == operator, the code above uses the = operator. This operator respects the current SET EXACT setting. The default is OFF which means that the left-hand string is only compared up to the length of the right-hand string. The expression always returns .T. if the value on the right side is an empty string. Logging on successfully is just a matter of not entering any password, at all!

**Check all string operations for unwanted side effects, especially =, <=, <, >, =>, #, != and <>.**

In general, deleting of files is one possibility to gain access to a system. In cases of an error, many applications pick a default value that is comfortable to the developer or user, but hardly secure. Suppose, you have the following function to obtain the return value of a modal VCX form:

```visual-basic
loForm = CREATEOBJECT(tcForm)
loForm.Show()
uRetVal = loForm.uRetVal
RETURN uRetVal

And call this function from the main program like this

llLoginOK = CallModalVCX("frmLogin")
```

In your tests, this function works flawlessly every time. But, what happens if there's an error while loading the form? If you, for instance, bind a textbox to a table and that table doesn't exist, Visual FoxPro doesn't create the form at all. In the code above, loForm would be .F. in the first line and cause errors in the next two lines. Hence, uRetVal would never be defined and the RETURN line would fail, too. **Visual FoxPro always returns a value from a function and a procedure. If you don't provide Visual FoxPro with a value, Visual FoxPro uses its default value: .T.  Since .T. is also the return value for a successful login, the user can login by renaming a file.**

**SQLi:**

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/2ea930fd-9cf6-4c57-ac28-b7a402be629c/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/34a77af7-b8b4-40b1-a8df-6b20dc4107a8/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/feda3a71-df9e-4c85-a2e0-ac016241a9f7/Untitled.png)

1: inputs are directly inserted in sql query making it vuln to sqli

2: parameterized query where `?lsCustode` variable is used to pass inputs making it safe from sqli

```visual-basic
//vuln to sqli
cSQL = "SELECT * FROM Users WHERE Username = '" + lcUsername + "' AND Password = '" + lcPassword + "'" 

//Proposed Fix code
PARAMETERS lcUsername, lcPassword
SELECT * FROM Users WHERE Username = ?lcUsername AND Password = ?lcPassword
```

More and more applications, though, do not save data in FoxPro tables, but in a SQL server database. To send a query to the SQL server, the application assembles SQL statements and often sends them with SQL Pass-Through to the SQL server. The following code tries to determine, if the password is correct. How long do you need to crack the following code?

```visual-basic
lcSQL = "SELECT * FROM User WHERE cUsername='"+;
        NVL(m.lcUser,"")+"' AND nHash="+TRANSFORM(NVL(lnHash,0))
IF SQLEXEC(lnHandle,m.lcSQL)>0 and RECCOUNT("SQLResult")>0
  * OK
ELSE
  * Error
ENDIF
```

The password query has been replaced through a hash value query, but the user name is still inserted into the query unchanged. That allows the hacker to modify the query as he wishes, for instance, when he enters the following user name:

' or 1=1 or 1=1

The resulting query always returns records. Additionally, the code checks if the SQL server returns records at all. The correct verification would be to check if exactly one record is returned. Multiple records in the result set would mean that there are multiple records for the same user and the same password. Such a constellation should have been prevented by the database. The possibilities are not limited to altering a simple query. Depending on the backend you can send multiple commands in a single command string. A hacker could create new users, change passwords and execute stored procedure in one pass from the login dialog.

code execution:

Similar problems do not only exist with `SQLEXEC()`. In Visual FoxPro, too, there are many possibilities to shoot oneself into the foot: macro substitution, **`EVALUATE()`** and **`SCRIPTEXEC()`.** If input values are used in conjunction with these features without further validation, a hacker has the entire arsenal of Visual FoxPro at his hands. As we will see later, you only need a single point in the application to execute code to turn off most conventional security mechanisms.

All input values have to be validated if they are in an acceptable form. The most important rule is to strip off all terminating characters. In Visual FoxPro this is the quotation mark, the single quotation mark, and square brackets that are used as string delimiters.

With HTML these are mostly "<" and ">" which you should remove from the input stream. In FoxPro you can easily use the CHRTRAN() function for that. For security reasons, you should focus on valid characters and remove all others:

```visual-basic
CHRTRAN(cString,CHRTRAN(cString,"ABCDE…Z1234567890",""),"")
```

The inner CHRTRAN removes all valid characters. The remaining characters are invalid. The outer CHRTRAN uses this string to remove invalid characters from the original string.

There are many possibilities to execute code in your Visual FoxPro application. For instance, a user could write FoxPro code into a text file and then enter the following expression in the report designer:

```visual-basic
SCRIPTEXEC(FILETOSTR("Datei.TXT"))
```

- _STARTUP or COMMAND line in the config.FPW
    - The **`_STARTUP`** line in the **`config.fpw`** file allows you to specify commands or scripts that will be executed when Visual FoxPro starts.
    - The **`_COMMAND`** line is similar to **`_STARTUP`** but is typically used to execute a single command or a series of commands.
- Macro substitution, EXECSCRIPT(), EVALUATE() or name expressions that are not validated.

Code obfuscation:

When protecting the application the goal is usually to prevent that someone can decompile the application and recover the sources. All products that don't produce machine code, but so-called P-code are especially vulnerable for de-compilation. If names like class names, method names, etc. are stored in clear text, because they are used to resolve dependencies, there are usually very good chances to restore the sources completely. There's a difference if the restored code reads

```visual-basic
PROCEDURE _1(_2,_3)
_1 = _2 * _3
RETURN _1*_1._1
```

```visual-basic
PROCEDURE LineTotal(tnAmount,tnPrice)
lnSum = tnAmount * tnPrice
RETURN lnSum * Tax.Rate
```

Insecure file operations:

```visual-basic
//vuln
lcFilename = "C:\data\userinput.txt"
STRTOFILE(lcUserInput, lcFilename)

//fix
lcFilename = "C:\data\userinput.txt"
STRTOFILE(lcUserInput, lcFilename)
```

Inadequate Authentication and Authorization:

To improve authentication and authorization, should not hardcode credentials in code. Instead, store user information securely and use a more robust authentication mechanism. Use a database to store user information and check the user's credentials against the database.

```visual-basic
* Vulnerable Authentication and Authorization
lcUsername = GETTEXT("Enter your username: ")
lcPassword = GETTEXT("Enter your password: ")

IF lcUsername = "admin" AND lcPassword = "password" //hardcoded credentials
    ? "Welcome, admin!"
ELSE
    ? "Access denied!"
ENDIF
```

**Unvalidated User Input:**

In the vulnerable code, there is no validation or sanitization of user input. This can lead to security vulnerabilities, including SQL injection. To fix this, you should validate and sanitize user inputs to ensure they meet your expected format and prevent malicious input. For example, to prevent SQL injection, you can use parameterized queries

```visual-basic
lcUsername = GETTEXT("Enter your username: ")
lcPassword = GETTEXT("Enter your password: ")

* Validate and sanitize inputs, assuming alphanumeric username and password
lcUsername = STRTRAN(lcUsername, "'", "")  && Remove single quotes
lcPassword = STRTRAN(lcPassword, "'", "")  && Remove single quotes

* Use parameterized query
lcSQL = "SELECT * FROM Users WHERE Username = ?lcUsername AND Password = ?lcPassword"
lnResult = SQLExec(lcSQL, "MyConnection")
IF lnResult > 0
    ? "Welcome, " + lcUsername + "!"
ELSE
    ? "Access denied!"
ENDIF
```

**Error Handling:**

In the vulnerable code, error handling is minimal, and sensitive information might be exposed in error messages. To improve error handling, you should provide informative error messages without revealing sensitive details. Additionally, consider implementing error logging to track issues in your application

```visual-basic
ON ERROR ? "An error occurred. Please contact support."
* Log error details to a file or database for analysis
```

**Don't let the user continue program execution in case of an error.**

Admittedly, causing an error to bypass a security check can be called an advanced technique. So far, we focused on comparing the value. But locating the record, too, could cause security issues. One variation of causing an error is

SEEK lcUser

While SEEK can search NULL values, this is only true if the indexed field also allows NULL values. Otherwise, SEEK cancels out with an error. If that error is ignored, the record pointer is still on the first record and the password validated. The hacker therefore doesn't have to know the name of the user. Since typically the first record contains a test user for the developer or the administrator, there're good chances that this attack results in using a privileged account.

**XSS;**

```visual-basic
//vuln to xss

lcUserInput = GETTEXT("Enter your name: ")
? "Hello, " + lcUserInput

//proposed fix code
lcUserInput = GETTEXT("Enter your name: ")
lcUserInput = HTMLencode(lcUserInput)
? "Hello, " + lcUserInput
```

**Secure Communication:**

If your application communicates over a network, you should use secure communication protocols, such as HTTPS, to encrypt data transmission and protect against eavesdropping. Visual FoxPro may not have native support for HTTPS, so if network security is a concern, consider using a more modern language or framework with built-in support for secure communication.

Cryptography:

**Data Encryption:**

If your application stores sensitive data like user passwords, it's essential to use strong encryption algorithms to protect that data. Never store passwords in plain text. Instead, store securely hashed and salted passwords. Here's a simplified example:

```visual-basic
* When storing a password:
lcPassword = "user_password"
lcSalt = GENERATEPASSWORDHASHSALT()
lcHashedPassword = HASH(lcPassword + lcSalt)
* Store lcSalt and lcHashedPassword in the database

* When verifying a password:
lcEnteredPassword = GETTEXT("Enter your password: ")
lcSalt = GETSALTFROMDATABASE(lcUsername)  && Retrieve the stored salt
lcHashedEnteredPassword = HASH(lcEnteredPassword + lcSalt)

IF lcHashedEnteredPassword = GETHASHEDPASSWORDFROMDATABASE(lcUsername)
    ? "Welcome, " + lcUsername + "!"
ELSE
    ? "Access denied!"
ENDIF
```

Diffusion:

- Hash: MD5, SHA512
- Encryption: AES, Blowfish
    - AES256 and Blowfish448 are cryptographically secure
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/87c45086-de28-4f8a-9eaf-b11abf6bb8f0/Untitled.png)
    

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/33d8e90f-1605-42ae-8817-8196fcd6c2e0/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/ed9fe83f-8a28-4fb8-b00e-e21dab44408d/Untitled.png)

Padding Oracle:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/35aa4ac1-f4d2-451b-9353-324fafbffd25/Untitled.png)

Password policy:

Database encryption:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/dca4b5aa-6451-44ed-afaf-03c41adb0cdd/Untitled.png)

Other:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/edcf750a-9ce3-427d-ae4b-5d29576d1bae/d3c11eac-644c-46e5-a076-d7eb0cae2f09/Untitled.png)

Here's a list of de-compilation tools for FoxPro:

| product | Web site |
| --- | --- |
| ReFox | http://www.xitech-europe.co.uk/ReFox.html |
| AntiPro | http://www.frog.cz/prod02.htm |
| UnFox | http://asm001.home.chinaren.com/source.htm http://www.weihong.com/tools.htm |
| SecurityFox | http://http://www.taketech.com/ |

Resources:

https://old.amu.ac.in/emp/studym/99999062.pdf

https://www.youtube.com/watch?v=jK1pq-4b60w

REFox XII: decompiler

https://hackfox.github.io/section5/s5c2.html

http://www.foxpert.com/docs/security.en.htm < important

https://vfpx.github.io/projects/

https://www.youtube.com/@geekgatherings/videos

https://owasp.org/www-pdf-archive/OWASP_SCP_Quick_Reference_Guide_v2.pdf

https://hackfox.github.io/

https://example-code.com/foxpro/
