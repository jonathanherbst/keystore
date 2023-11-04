from fpdf import FPDF
import qrcode

import io

def generate_qr_code(name, secret):
    return qrcode.make(" ".join((name, secret.hex)), image_factory=qrcode.image.pure.PyPNGImage)

class KeyReport:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.add_page()
        self.pdf.set_font('helvetica', size=10)

    def add_key(self, name, secret):
        qr = generate_qr_code(name, secret)
        qr_file = io.BytesIO()
        qr.save(qr_file)

        self.pdf.cell(text="Name: " + name)
        self.pdf.ln()
        self.pdf.cell(text="Key: " + secret.hex)
        self.pdf.ln()
        self.pdf.image(qr_file, w=40, keep_aspect_ratio=True)
        self.pdf.ln()

    def save(self, path):
        self.pdf.output(path)

def generate_key_store_report(path, key_store):
    report = KeyReport()
    for key in key_store.all_keys:
        report.add_key(key.name, key.secret)
    report.save(path)