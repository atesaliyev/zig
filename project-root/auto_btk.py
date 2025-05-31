# auto_btk.py

import requests
from bs4 import BeautifulSoup
import base64
import time
import logging
from datetime import datetime
import urllib3

# Anti-Captcha çağrılarında HTTPS sertifika doğrulamasını kapatmak için:
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutoBTKReporter:
    """
    BTK İhbarweb formunu otomatik olarak doldurup CAPTCHA çözerek gönderir.
    Domain ve açıklama (detay) parametreleriyle formu POST eder.
    Anti-Captcha API anahtarınızı `anti_captcha_key` değişkenine yazmalısınız.
    """
    def __init__(self, anti_captcha_key: str):
        self.form_url = "http://www.ihbarweb.org.tr/ihbar.php?subject=7"
        self.anti_captcha_key = anti_captcha_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "tr,en-US;q=0.7,en;q=0.3"
        })

    def _fetch_form_page(self) -> str:
        """İhbarweb form sayfasını HTTP GET ile indirir ve HTML içeriğini döner."""
        logger.info("Form sayfası indiriliyor...")
        try:
            # Burada http://... kullanıyoruz, verify=False ile HTTPS sertifika hatalarını engelleriz
            resp = self.session.get(self.form_url, timeout=60, verify=False, allow_redirects=True)
            resp.raise_for_status()
            logger.info("Form sayfası başarıyla alındı (HTTP %s)", resp.status_code)
            return resp.text
        except requests.RequestException as e:
            logger.error("Form sayfası alınamadı: %s", e)
            raise

    def _fetch_captcha_image(self, soup: BeautifulSoup) -> bytes:
        """Form HTML'den CAPTCHA <img id='captcha'> etiketini bulur ve resmi indirir."""
        logger.info("CAPTCHA resmi aranıyor...")
        captcha_img = soup.find("img", id="captcha")
        if not captcha_img or not captcha_img.get("src"):
            raise RuntimeError("CAPTCHA resmi bulunamadı.")

        # src muhtemelen "captcha/get_captcha.php?rnd=XYZ" şeklinde olur
        src = captcha_img["src"].lstrip("/")
        captcha_url = f"http://www.ihbarweb.org.tr/{src}"
        logger.info("CAPTCHA URL: %s", captcha_url)
        try:
            resp = self.session.get(captcha_url, timeout=60, verify=False)
            resp.raise_for_status()
            logger.info("CAPTCHA resmi indirildi (boyut: %d bayt)", len(resp.content))
            return resp.content
        except requests.RequestException as e:
            logger.error("CAPTCHA resmi indirilemedi: %s", e)
            raise

    def _solve_captcha(self, image_bytes: bytes) -> str:
        """
        Anti-Captcha API kullanarak base64 olarak verilen CAPTCHA resmini çözer.
        Dönen çözüm metnini geri döner.
        """
        logger.info("Anti-Captcha görevi oluşturuluyor...")
        create_task_url = "https://api.anti-captcha.com/createTask"
        get_result_url = "https://api.anti-captcha.com/getTaskResult"

        # Resmi base64 koduna çevir
        b64 = base64.b64encode(image_bytes).decode("utf-8")
        task_payload = {
            "clientKey": self.anti_captcha_key,
            "task": {
                "type": "ImageToTextTask",
                "body": b64,
                "phrase": False,
                "case": True,
                "numeric": 0,
                "math": False,
                "minLength": 4,
                "maxLength": 6
            }
        }

        try:
            ct_resp = requests.post(create_task_url, json=task_payload, timeout=60, verify=False)
            ct_resp.raise_for_status()
            ct_data = ct_resp.json()
            if ct_data.get("errorId", 1) != 0:
                raise RuntimeError(f"Anti-Captcha createTask hatası: {ct_data.get('errorDescription')}")
            task_id = ct_data["taskId"]
            logger.info("Anti-Captcha görev ID %s oluşturuldu. Sonuç bekleniyor...", task_id)
        except requests.RequestException as e:
            logger.error("Anti-Captcha createTask isteği başarısız: %s", e)
            raise

        # Sonuç hazır olana kadar bekle (maksimum 30 deneme)
        max_attempts = 30
        while max_attempts > 0:
            time.sleep(2)
            try:
                res_payload = {"clientKey": self.anti_captcha_key, "taskId": task_id}
                res_resp = requests.post(get_result_url, json=res_payload, timeout=60, verify=False)
                res_resp.raise_for_status()
                res_data = res_resp.json()
                if res_data.get("status") == "ready":
                    solution = res_data["solution"]["text"]
                    logger.info("CAPTCHA çözüldü: %s", solution)
                    return solution
                else:
                    logger.info("CAPTCHA henüz hazır değil, bekleniyor... (%d deneme kaldı)", max_attempts)
            except requests.RequestException as e:
                logger.warning("CAPTCHA sonucu sorgulama hatası: %s", e)
            max_attempts -= 1

        raise TimeoutError("Anti-Captcha: CAPTCHA çözümü zaman aşımına uğradı")

    def submit_report(self, domain: str, description: str = None, max_retries: int = 3) -> dict:
        """
        İhbarweb formunu verilen domain ve description ile doldurur, CAPTCHA çözer ve POST eder.
        description eğer None veya boş string verilirse, otomatik "Phishing domain report: {domain}" formatı kullanılır.
        Başarılıysa {'success': True, 'message': ...}, başarısızsa {'success': False, 'message': ...} döner.
        """
        attempt = 0
        # Eğer description boşsa, default olarak domain üzerinden bir açıklama üret
        if not description:
            description = f"Phishing domain report: {domain}"

        while attempt < max_retries:
            attempt += 1
            logger.info("İhbar denemesi %d/%d: %s", attempt, max_retries, domain)

            try:
                # 1) Form sayfasını indir
                html = self._fetch_form_page()
                soup = BeautifulSoup(html, "html.parser")

                # 2) CAPTCHA resmini al & çöz
                logger.info("CAPTCHA resmi indiriliyor...")
                img_bytes = self._fetch_captcha_image(soup)
                logger.info("CAPTCHA çözümü başlıyor...")
                captcha_text = self._solve_captcha(img_bytes)

                # 3) Form verilerini hazırla
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                form_data = {
                    "ihbar": "7",
                    "adres": domain,
                    "detay": description,        # description parametresi kullanılıyor
                    "tar": now_str,
                    "suc": "2",
                    "ad": "",
                    "soyad": "",
                    "tckimlik": "",
                    "email": "",
                    "tel": "",
                    "security_code": captcha_text
                }

                # 4) Formu POST et
                logger.info("Form verileri gönderiliyor...")
                post_resp = self.session.post(
                    self.form_url,
                    data=form_data,
                    headers={
                        "Origin": "http://www.ihbarweb.org.tr",
                        "Referer": self.form_url
                    },
                    timeout=60,
                    allow_redirects=False,
                    verify=False
                )

                status_code = post_resp.status_code
                body_lower = post_resp.text.lower()

                # 5) Başarı kriterlerini kontrol et
                if (
                    status_code == 302 or
                    "ihbarsonrasi.html" in body_lower or
                    "teşekkür" in body_lower or
                    "ihbarınız alınmıştır" in body_lower
                ):
                    logger.info("İhbar başarıyla gönderildi!")
                    return {"success": True, "message": "Form başarılı şekilde gönderildi"}
                else:
                    logger.warning(
                        "Form gönderimi başarısız (HTTP %s). %s",
                        status_code,
                        "Yeniden denenecek." if attempt < max_retries else "Son deneme."
                    )

            except Exception as e:
                logger.error("Deneme %d hata: %s", attempt, e)

            # Hata durumunda kısa bir bekleme
            time.sleep(2)

        return {"success": False, "message": f"{max_retries} denemede ihbar gönderilemedi."}


if __name__ == "__main__":
    # Anti-Captcha API anahtarınızı buraya yazın:
    ANTI_CAPTCHA_KEY = "2355d15825a3020693fc4be1b363f523"
    if not ANTI_CAPTCHA_KEY or ANTI_CAPTCHA_KEY.startswith("BURAYA"):
        print("Lütfen ANTI_CAPTCHA_KEY değerini kendi anahtarınızla değiştirin.")
        exit(1)

    # Örnek çağrı
    reporter = AutoBTKReporter(anti_captcha_key=ANTI_CAPTCHA_KEY)
    result = reporter.submit_report(domain="facebooksun.com", description="Bu bir test açıklaması", max_retries=3)
    print(result)
