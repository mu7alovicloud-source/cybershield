"""Multilingual, evidence-aware cybersecurity knowledge base for CyberShield AI."""
from __future__ import annotations

KB = {
    "virus": {
        "uz": "Virus — o‘zini boshqa fayllarga qo‘shib tarqatishi mumkin bo‘lgan zararli dastur turi. Shubhali faylning o‘zi avtomatik ravishda virus degani emas.",
        "en": "A virus is malware that can attach to other files and spread when the infected content is used. A suspicious file is not automatically a virus.",
        "ru": "Вирус — вредоносная программа, способная присоединяться к другим файлам и распространяться при их использовании. Подозрительный файл не обязательно является вирусом.",
    },
    "malware": {
        "uz": "Malware — zarar yetkazish, ma’lumot o‘g‘irlash yoki tizim faoliyatini buzish uchun yaratilgan zararli dasturlar uchun umumiy atama. Virus, Trojan, worm va ransomware uning turlariga misol.",
        "en": "Malware is the general term for software designed to harm systems, steal information, or disrupt operations. Viruses, trojans, worms, and ransomware are examples.",
        "ru": "Вредоносное ПО — общий термин для программ, предназначенных для ущерба, кражи данных или нарушения работы системы. Вирусы, трояны, черви и вымогатели — примеры.",
    },
    "trojan": {
        "uz": "Trojan foydali yoki oddiy dasturga o‘xshab ko‘rinishi mumkin, ammo ishga tushganda zararli faoliyat bajarishi mumkin. Baholashda fayl tuzilishi, xatti-harakat va boshqa mustaqil dalillar birgalikda ko‘riladi.",
        "en": "A trojan disguises itself as legitimate or useful software but may perform malicious activity after execution. Good detection combines structure, behavior, and independent evidence.",
        "ru": "Троян может выглядеть как обычная или полезная программа, но после запуска выполнять вредоносные действия. Надёжная оценка объединяет структуру, поведение и независимые признаки.",
    },
    "worm": {
        "uz": "Worm — foydalanuvchi harakatini talab qilmasdan tarmoq yoki tizimlar bo‘ylab tarqalishga qodir malware turi. Uning asosiy belgisi — o‘z-o‘zini tarqatish qobiliyati.",
        "en": "A worm is malware designed to spread between systems, often without requiring a user to manually copy or launch it. Self-propagation is its defining characteristic.",
        "ru": "Червь — вредоносная программа, способная распространяться между системами, часто без ручного копирования или запуска пользователем. Главное свойство — самораспространение.",
    },
    "ransomware": {
        "uz": "Ransomware odatda fayllarni shifrlaydi yoki tizimga kirishni cheklaydi va to‘lov talab qiladi. Zaxira nusxalari, yangilanishlar, kuchli autentifikatsiya va erta aniqlash muhim himoyalardir.",
        "en": "Ransomware typically encrypts files or restricts access and demands payment. Backups, updates, strong authentication, and early detection are important defenses.",
        "ru": "Вымогательское ПО обычно шифрует файлы или ограничивает доступ и требует оплату. Важны резервные копии, обновления, сильная аутентификация и раннее обнаружение.",
    },
    "phishing": {
        "uz": "Phishing — foydalanuvchini aldab parol, karta ma’lumoti yoki boshqa maxfiy ma’lumotni berishga undaydigan hujum. URL tahlilida domen, yo‘l, impersonation va boshqa indikatorlar tekshiriladi.",
        "en": "Phishing is an attack that tricks people into revealing credentials, payment data, or other sensitive information. URL analysis can examine domains, paths, impersonation, and other indicators.",
        "ru": "Фишинг — атака, которая обманом заставляет человека раскрыть учётные данные, платёжную или другую чувствительную информацию. При анализе URL проверяются домен, путь, имитация бренда и другие признаки.",
    },
    "spyware": {
        "uz": "Spyware foydalanuvchi faoliyati yoki ma’lumotlarini yashirin kuzatishga urinadigan zararli dastur turidir.",
        "en": "Spyware is malware designed to monitor activity or collect information without appropriate user awareness or authorization.",
        "ru": "Шпионское ПО — вредоносная программа, предназначенная для скрытого наблюдения за активностью или сбора информации без надлежащего согласия.",
    },
    "rootkit": {
        "uz": "Rootkit tizimdagi mavjudligini yashirish va yuqori imtiyozli nazoratni saqlashga urinadigan zararli komponentlar oilasidir. Bunday holatda chuqur telemetriya va offline tekshiruv kerak bo‘lishi mumkin.",
        "en": "A rootkit is a class of malicious components that attempts to hide its presence and maintain privileged control. Deep telemetry or offline analysis may be required.",
        "ru": "Руткит — класс вредоносных компонентов, пытающихся скрыть своё присутствие и сохранить привилегированный контроль. Может потребоваться глубокая телеметрия или офлайн-анализ.",
    },
    "keylogger": {
        "uz": "Keylogger klaviatura kiritmalarini kuzatishga urinadigan dastur yoki komponent. Himoyada endpoint telemetriyasi, jarayon kelib chiqishi va shubhali persistence muhim.",
        "en": "A keylogger attempts to capture keyboard input. Defensive analysis can examine endpoint telemetry, process provenance, and suspicious persistence.",
        "ru": "Кейлоггер пытается перехватывать ввод с клавиатуры. Для защиты важны телеметрия конечной точки, происхождение процесса и подозрительная persistence.",
    },
    "botnet": {
        "uz": "Botnet — masofadan boshqariladigan zararlangan qurilmalar to‘plami. Tarmoqdagi noodatiy beaconing va process xatti-harakati aniqlashda foydali dalil bo‘lishi mumkin.",
        "en": "A botnet is a collection of compromised devices controlled remotely. Unusual beaconing and process behavior can be useful detection evidence.",
        "ru": "Ботнет — совокупность скомпрометированных устройств с удалённым управлением. Необычные beacon-соединения и поведение процессов могут быть полезными признаками.",
    },
    "sandbox": {
        "uz": "Sandbox — shubhali obyektni asosiy tizimdan ajratilgan muhitda kuzatish usuli. Noma’lum kodni hostda bevosita ishga tushirish xavfsiz yondashuv emas.",
        "en": "A sandbox is an isolated environment for observing suspicious objects. Direct execution of unknown code on the host is not a safe approach.",
        "ru": "Sandbox — изолированная среда для наблюдения за подозрительными объектами. Прямой запуск неизвестного кода на хосте небезопасен.",
    },
    "edr": {
        "uz": "EDR endpointdagi jarayon, fayl, tarmoq va boshqa telemetriyani kuzatib, shubhali faoliyatni aniqlash va hodisaga javob berishga yordam beradi.",
        "en": "EDR monitors endpoint processes, files, network activity, and other telemetry to detect suspicious behavior and support incident response.",
        "ru": "EDR отслеживает процессы, файлы, сетевую активность и другую телеметрию конечной точки для обнаружения подозрительного поведения и реагирования.",
    },
    "antivirus": {
        "uz": "Antivirus zararli fayllarni aniqlash, bloklash yoki karantinga olishga yordam beradi. Zamonaviy himoya faqat imzoga emas, xatti-harakat va boshqa dalillarga ham tayanadi.",
        "en": "Antivirus software helps detect, block, or quarantine malicious files. Modern protection also uses behavior and multiple evidence sources, not signatures alone.",
        "ru": "Антивирус помогает обнаруживать, блокировать и помещать вредоносные файлы в карантин. Современная защита использует не только сигнатуры, но и поведение с другими признаками.",
    },
    "firewall": {
        "uz": "Firewall tarmoq ulanishlarini belgilangan qoidalar asosida nazorat qiladi. U endpoint monitoring va phishing himoyasini to‘liq almashtirmaydi, balki qo‘shimcha qatlam bo‘ladi.",
        "en": "A firewall controls network connections according to configured rules. It complements endpoint monitoring and phishing protection rather than replacing them.",
        "ru": "Брандмауэр контролирует сетевые соединения по заданным правилам. Он дополняет мониторинг конечной точки и защиту от фишинга, а не заменяет их.",
    },
    "quarantine": {
        "uz": "Karantin shubhali faylni ishlatiladigan joydan ajratib, qayta tiklash imkonini saqlashga qaratilgan containment usulidir. Bu ko‘pincha darhol o‘chirishdan xavfsizroq.",
        "en": "Quarantine isolates a suspicious file from normal use while preserving controlled recovery metadata. It is often safer than immediately deleting the original.",
        "ru": "Карантин изолирует подозрительный файл от обычного использования, сохраняя контролируемую возможность восстановления. Часто это безопаснее немедленного удаления.",
    },
    "hash": {
        "uz": "Hash, masalan SHA-256, fayl mazmunidan hosil bo‘ladigan raqamli izdir. U fayl identifikatsiyasi va qayta tekshirish uchun foydali, ammo hashning o‘zi fayl zararli ekanini isbotlamaydi.",
        "en": "A hash such as SHA-256 is a digital fingerprint derived from file content. It helps identify and verify a file, but a hash alone does not prove maliciousness.",
        "ru": "Хеш, например SHA-256, — цифровой отпечаток содержимого файла. Он полезен для идентификации и проверки, но сам по себе не доказывает вредоносность.",
    },
    "false_positive": {
        "uz": "False positive — xavfsiz obyektning noto‘g‘ri ravishda xavfli deb baholanishi. Shuning uchun CyberShield bitta zaif indikatorni yakuniy hukm deb qabul qilmasligi kerak.",
        "en": "A false positive is a safe object incorrectly classified as malicious. A robust detector should not treat one weak indicator as final proof.",
        "ru": "Ложное срабатывание — безопасный объект, ошибочно классифицированный как вредоносный. Надёжный детектор не должен считать один слабый признак окончательным доказательством.",
    },
    "zero_day": {
        "uz": "Zero-day — himoya yoki ishlab chiquvchi uchun hali to‘liq ma’lum bo‘lmagan yoki tuzatish mavjud bo‘lmagan zaiflik bilan bog‘liq xavf. Bunday holatda qatlamli himoya va ehtiyotkor containment muhim.",
        "en": "A zero-day involves a vulnerability or attack path that is not yet fully known or patched by the defender or vendor. Layered protection and cautious containment are important.",
        "ru": "Zero-day связан с уязвимостью или способом атаки, который ещё не полностью известен или не исправлен защитником/поставщиком. Важны многоуровневая защита и осторожное containment.",
    },
    "incident_response": {
        "uz": "Incident response — hodisani aniqlash, tushunish, containment, remediation va verification bosqichlari orqali xavfni boshqarish jarayoni.",
        "en": "Incident response is the process of detecting, understanding, containing, remediating, and verifying a security incident.",
        "ru": "Incident response — процесс обнаружения, понимания, сдерживания, устранения и проверки последствий инцидента безопасности.",
    },
    "two_factor": {
        "uz": "2FA/MFA hisobga kirishda paroldan tashqari qo‘shimcha tasdiqlash omilini talab qiladi. Bu phishing yoki parol sizib chiqishi ta’sirini kamaytirishga yordam beradi.",
        "en": "2FA/MFA requires an additional authentication factor beyond a password. It can reduce the impact of stolen passwords and some phishing attacks.",
        "ru": "2FA/MFA требует дополнительный фактор аутентификации помимо пароля. Это снижает последствия кражи пароля и некоторых фишинговых атак.",
    },
    "cybershield": {
        "uz": "CyberShield — fayl va URL tahlili, endpoint telemetriyasi, AI yordamchisi, containment/quarantine va xavfsiz tahlil laboratoriyasini birlashtiruvchi defensive security platforma.",
        "en": "CyberShield is a defensive security platform combining file and URL analysis, endpoint telemetry, an AI copilot, containment/quarantine, and safe analysis capabilities.",
        "ru": "CyberShield — защитная платформа, объединяющая анализ файлов и URL, телеметрию конечной точки, AI Copilot, containment/карантин и безопасный анализ.",
    },
}

ALIASES = {
    "virus":"virus", "viruz":"virus", "virs":"virus",
    "malware":"malware", "зловред":"malware", "вредонос":"malware",
    "trojan":"trojan", "troyan":"trojan", "троян":"trojan",
    "worm":"worm", "червь":"worm",
    "phishing":"phishing", "fishing":"phishing", "фишинг":"phishing",
    "ransomware":"ransomware", "вымогатель":"ransomware",
    "spyware":"spyware", "шпион":"spyware",
    "rootkit":"rootkit", "руткит":"rootkit",
    "keylogger":"keylogger", "кейлоггер":"keylogger",
    "botnet":"botnet", "ботнет":"botnet",
    "sandbox":"sandbox", "песочниц":"sandbox",
    "edr":"edr", "антивирус":"antivirus", "antivirus":"antivirus",
    "firewall":"firewall", "брандмауэр":"firewall",
    "quarantine":"quarantine", "karantin":"quarantine", "карантин":"quarantine",
    "hash":"hash", "sha-256":"hash", "sha256":"hash",
    "false positive":"false_positive", "xato aniqlash":"false_positive", "ложн":"false_positive",
    "zero-day":"zero_day", "0-day":"zero_day", "нулевого дня":"zero_day",
    "incident response":"incident_response", "hodisaga javob":"incident_response",
    "2fa":"two_factor", "mfa":"two_factor", "ikki bosqich":"two_factor",
    "cybershield":"cybershield", "kibershild":"cybershield",
}

COMPARES = {
    frozenset(("virus", "worm")):
        {"uz":"Virus ko‘pincha faylga birikib tarqaladi; worm esa o‘z-o‘zini tarmoq yoki tizimlar bo‘ylab tarqatishga ko‘proq moslashgan.", "en":"A virus commonly spreads by attaching to files; a worm is primarily designed for self-propagation between systems or networks.", "ru":"Вирус обычно распространяется через заражённые файлы; червь прежде всего рассчитан на самостоятельное распространение между системами или сетями."},
    frozenset(("trojan", "virus")):
        {"uz":"Virus tarqalish mexanizmi bilan, Trojan esa o‘zini boshqa dasturdek ko‘rsatishi bilan ajraladi. Ular bir-birini inkor qilmaydi.", "en":"A virus is defined mainly by its propagation mechanism, while a trojan is defined by masquerading as legitimate software. The concepts can overlap.", "ru":"Вирус определяется прежде всего механизмом распространения, а троян — маскировкой под легитимную программу. Эти понятия могут пересекаться."},
    frozenset(("edr", "antivirus")):
        {"uz":"Antivirus ko‘proq zararli obyektni aniqlash/bloklashga yo‘naltiriladi; EDR esa endpointdagi jarayonlar, fayllar va tarmoq telemetriyasini kengroq kuzatib, hodisani tekshirishga yordam beradi.", "en":"Antivirus focuses strongly on detecting and blocking malicious objects; EDR provides broader endpoint telemetry and investigation/response capabilities.", "ru":"Антивирус в основном обнаруживает и блокирует вредоносные объекты; EDR даёт более широкую телеметрию конечной точки и возможности расследования/реагирования."},
    frozenset(("sandbox", "quarantine")):
        {"uz":"Sandbox — obyektni izolyatsiyada kuzatish; quarantine esa faylni odatiy foydalanishdan ajratib qo‘yish. Ularning maqsadi bir xil emas.", "en":"A sandbox isolates an object for controlled observation; quarantine isolates a file from normal use. They solve different problems.", "ru":"Sandbox изолирует объект для контролируемого наблюдения; карантин изолирует файл от обычного использования. Это разные задачи."},
}


def topics_in(q: str) -> list[str]:
    q = (q or "").lower()
    found = []
    for alias, topic in sorted(ALIASES.items(), key=lambda x: -len(x[0])):
        if alias in q and topic not in found:
            found.append(topic)
    return found


def topic_for(q: str) -> str | None:
    topics = topics_in(q)
    return topics[0] if topics else None
