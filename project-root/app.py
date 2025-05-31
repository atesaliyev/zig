from flask import Flask, request, jsonify
from auto_btk import AutoBTKReporter
import os

app = Flask(__name__)

# Çevre değişkeninden Anti-Captcha anahtarını oku (veya direk sabitle)
ANTI_CAPTCHA_KEY = os.getenv("ANTI_CAPTCHA_KEY", "2355d15825a3020693fc4be1b363f523")
# Dilersen bu sabit değil de prod ortamında ENV’den gelsin

# Bir seferlik reporter örneği yarat (ya istek başına da yaratabilirsin)
# Ama aynı session nesnesini kullanmak biraz daha hızlı olur
reporter = AutoBTKReporter(anti_captcha_key=ANTI_CAPTCHA_KEY)

@app.route("/api/report", methods=["POST"])
def report_domain():
    """
    İstek gövdesinden JSON olarak { "domain": "example.com" } gelmeli.
    İstersen max_retries parametresi de ekleyebilirsin.
    """
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "Domain parametresi eksik."}), 400

    # Opsiyonel: max_retries göndersin mi?
    max_retries = int(data.get("max_retries", 3))

    try:
        # Bot çalışacak, sonuç dict formatında dönecek
        result = reporter.submit_report(domain=domain, max_retries=max_retries)
        # result örn: {"success": True, "message": "..."}
        return jsonify(result)
    except Exception as e:
        # Hata varsa mesajı da dön
        return jsonify({"success": False, "message": f"Sunucu hatası: {str(e)}"}), 500

if __name__ == "__main__":
    # Prod’da gunicorn/uvicorn ile run edin, lokal test için:
    app.run(host="0.0.0.0", port=5000, debug=False)
