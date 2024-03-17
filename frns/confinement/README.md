# Cyber Apocalypse 2024

# Confinement | hard | forensics

> "Our clan's network has been infected by a cunning ransomware attack, encrypting irreplaceable data essential for our relentless rivalry with other factions. With no backups to fall back on, we find ourselves at the mercy of unseen adversaries, our fate uncertain. Your expertise is the beacon of hope we desperately need to unlock these encrypted files and reclaim our destiny in The Fray.
Note: The valuable data is stored under \Documents\Work"
>

## Synopsys

The challenge is a real-world like forensincs tasks, like a blue-teamer. We are given a `Confinement.ad1` file, approximatelly 260 MB.

We might know already what this file format is, but let's find out what this extension is about.

> An .ad1 file is a forensic image file format used by AccessData in their forensic software tools, including FTK Imager. FTK (Forensic Toolkit) Imager is a powerful and versatile imaging tool used in digital forensics for  the creation, examination, and analysis of disk images. The .ad1 format is proprietary to AccessData and is specifically designed to encapsulate disk images or contents of a disk drive, including its file system. This file  format is used for securely preserving digital evidence, which can be analyzed later.
>

Alright, this means we're going to use the FTK Imager software. 

## Analysis

Let's launch the FTK Imager. Let's load up this volume and dig deep. File > Add Evidence Item > Image file.

As per the channel narrative, we can start looking under the `\Documents\Work` folder first. But then examine the whole drive, of course.

Right from the first we can realize that this device was hit by a ransomware attack. The additional `.korp` suffix extension is hinting on this. Then we also find the `ULTIMATUM.hta` which is a ransom note. 

```The Fray Ultimatum
🔒 ATTENTION FACTIONS 🔒
What's this? Your precious data seems to have fallen into the hands of KORP™, the all-powerful overseer of The Fray.
Consider it a test of your faction's mettle. Will you rise to the challenge or crumble under the weight of your encrypted files?
For further instructions, send your Faction ID to the provided email address:
Email: fraycrypter@korp.com
💰💣 ACT SWIFTLY OR FACE YOUR DEMISE 💣💰
🚫 DO NOT attempt to disrupt the encryption process; it's futile 😏
🚫 DO NOT rely on feeble antivirus software; they are but toys in our hands 😉
🚫 DO NOT dream of accessing your encrypted files; they are now under our control 😈
🚫 DO NOT trust anyone, not even us, for decryption
Failure to comply will result in the permanent loss of your precious data 💥
Once the clock strikes zero, your data will be lost forever 🕒
Before even thinking of payment, you may submit up to 3 test files for free decryption, each file not exceeding 5 MB in size 📎
And remember, these test files should contain no vital information!
***PAYMENT IS STRICTLY FORBIDDEN UNTIL TEST FILE DECRYPTION***
```



![image](https://github.com/respawnRW/writeups/assets/163560495/1bf20ef2-b7b3-4deb-b89c-ecae004978a1)



## Malware Hunting

Flag: `HTB{2_f34r_1s_4_ch01ce_322720914448bf9831435690c5835634}`

Be done with it.

Hope you find it useful,

`--RW`
