import requests

def get_subdomains(domain):
    subdomains = []
    total_subdomains = 0

    sources = [
        {
            'name': 'CertSh',
            'url': f'https://crt.sh/?q=%.{domain}&output=json'
        },
        {
            'name': 'BufferOver',
            'url': f'https://dns.bufferover.run/dns?q=.{domain}'
        },
        {
            'name': 'Virustotal',
            'url': f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
        },
        {
            'name': 'Rapid7 FDNS',
            'url': f'https://opendata.rapid7.com/greynoise/{domain}'
        },
        {
            'name': 'SecurityTrails',
            'url': f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
        },
        {
            'name': 'ThreatCrowd',
            'url': f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        },
        {
            'name': 'AlienVault OTX',
            'url': f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
        },
        {
            'name': 'C99.nl',
            'url': f'https://c99.nl/api/subdomain/{domain}'
        }
        # Adicione mais fontes públicas aqui, se desejar.
    ]

    for source in sources:
        try:
            response = requests.get(source['url'])
            if response.status_code == 200:
                data = response.json()
                if source['name'] == 'CertSh':
                    subdomains.extend([record['name_value'] for record in data])
                elif source['name'] == 'BufferOver':
                    subdomains.extend(data.get('FDNS_A', []))
                elif source['name'] == 'Virustotal':
                    subdomains.extend(data.get('data', {}).get('attributes', {}).get('subdomains', []))
                elif source['name'] == 'Rapid7 FDNS':
                    subdomains.extend(data.get('subdomains', []))
                elif source['name'] == 'SecurityTrails':
                    subdomains.extend(data.get('subdomains', []))
                elif source['name'] == 'ThreatCrowd':
                    subdomains.extend(data.get('subdomains', []))
                elif source['name'] == 'AlienVault OTX':
                    subdomains.extend([record['hostname'] for record in data.get('passive_dns', [])])
                elif source['name'] == 'C99.nl':
                    subdomains.extend(data.get('subdomains', []))
        except requests.exceptions.RequestException as e:
            print(f"Erro ao consultar subdomínios em {source['name']}: {str(e)}")

    total_subdomains = len(subdomains)

    print("\nSubdomínios encontrados para {}:".format(domain))
    if total_subdomains > 0:
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("Nenhum subdomínio encontrado.")

    print("\nTotal de subdomínios analisados: {}".format(len(sources)))
    print("Total de subdomínios encontrados: {}".format(total_subdomains))

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python subverify.py <domínio>")
        sys.exit(1)

    domain = sys.argv[1]
    get_subdomains(domain)
