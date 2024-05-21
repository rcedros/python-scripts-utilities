import qrcode

def gerar_qrcode(data, nome_arquivo="qrcode_kong.png"):
    # Cria uma instância QRCode
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Adiciona os dados ao QRCode
    qr.add_data(data)
    qr.make(fit=True)
    
    # Cria uma imagem do QRCode
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Salva a imagem em um arquivo
    img.save(nome_arquivo)

# Testando a função
data = "https://site.com.br/company/why-kong"
gerar_qrcode(data)
