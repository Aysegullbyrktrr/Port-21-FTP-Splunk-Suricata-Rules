### Suricata Rules

Suricata, ağ trafiğini izlemek ve anormal veya zararlı etkinlikleri tespit etmek için kullanılan bir açık kaynaklı tehdit algılama motorudur. İşte port 21 (FTP) ile ilgili bazı Suricata kuralları:

1. **FTP Login Attempt Detection:** FTP sunucusuna bir kullanıcı adı gönderildiğinde tetiklenir.
   ```suricata
   alert tcp any any -> any 21 (msg:"FTP login attempt"; flow:to_server,established; content:"USER "; nocase; sid:1000001; rev:1;)
   ```
2. **FTP Successful Login:** Başarılı bir FTP oturumu açıldığında tetiklenir.
   ```suricata
   alert tcp any any -> any 21 (msg:"FTP successful login"; flow:to_server,established; content:"230 Login successful"; nocase; sid:1000002; rev:1;)
   ```

3. **FTP Failed Login:** Başarısız bir FTP oturumu açma girişimi tespit edildiğinde tetiklenir.
   ```suricata
   alert tcp any any -> any 21 (msg:"FTP failed login"; flow:to_server,established; content:"530 Login incorrect"; nocase; sid:1000003; rev:1;)
   ```

4. **FTP File Upload:** FTP sunucusuna bir dosya yüklendiğinde tetiklenir.
   ```suricata
   alert tcp any any -> any 21 (msg:"FTP file upload detected"; flow:to_server,established; content:"STOR "; nocase; sid:1000004; rev:1;)
   ```

5. **FTP File Download:** FTP sunucusundan bir dosya indirildiğinde tetiklenir.
   ```suricata
   alert tcp any any -> any 21 (msg:"FTP file download detected"; flow:to_server,established; content:"RETR "; nocase; sid:1000005; rev:1;)
   ```


   ### Splunk Queries

Splunk, büyük veri analizi ve güvenlik bilgisi ile olay yönetimi (SIEM) için kullanılan güçlü bir platformdur. İşte FTP etkinliklerini izlemek ve olası tehditleri tespit etmek için bazı Splunk sorguları:

1. **FTP Login Attempts:** Kullanıcı adı gönderme girişimlerini sayar ve kaynak IP adresi ve kullanıcı adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "USER" | stats count by src_ip, user
   ```

2. **FTP Successful Logins:** Başarılı oturum açma girişimlerini sayar ve kaynak IP adresi ve kullanıcı adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "230 Login successful" | stats count by src_ip, user
   ```

3. **FTP Failed Logins:** Başarısız oturum açma girişimlerini sayar ve kaynak IP adresi ve kullanıcı adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "530 Login incorrect" | stats count by src_ip, user
   ```

4. **FTP File Uploads:** Dosya yükleme girişimlerini sayar ve kaynak IP adresi ve dosya adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "STOR" | stats count by src_ip, file_name
   ```

5. **FTP File Downloads:** Dosya indirme girişimlerini sayar ve kaynak IP adresi ve dosya adına göre gruplar.
   ```splunk
   index=your_index sourcetype=your_sourcetype "RETR" | stats count by src_ip, file_name

   
   
   
   Bu kurallar ve sorgular, FTP trafiğini izleyerek olası tehditleri tespit etmek için kullanılabilir.