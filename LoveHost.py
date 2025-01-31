#!/usr/bin/python  
import argparse  
import subprocess  
import signal  
import sys  
from termcolor import colored  
from concurrent.futures import ThreadPoolExecutor  
from pyfiglet import Figlet  
from datetime import datetime  
from nmap import PortScanner  


class BannerManager:  
    """  
    Clase encargada de manejar el banner y los mensajes impresos en pantalla.  
    """  
    def __init__(self, text="LOVEHOST", font="banner3"):  
        self.text = text  
        self.font = font  

    def print_figlet(self):  
       
        figlet = Figlet(font=self.font)  
        ascii_art = figlet.renderText(self.text)  
        try:  
            lolcat_process = subprocess.Popen(['lolcat'], stdin=subprocess.PIPE)  
            lolcat_process.communicate(input=ascii_art.encode())  
        except FileNotFoundError:  
            print(ascii_art)  

    def print_banner(self):  
        self.print_figlet()  
        print("\n@puerto4444")  
        print("-" * 30)  



class HostScanner:  
    """  
    Clase que encapsula la lógica para escanear hosts, validar targets y  
    guardar los resultados.  
    """  
    def __init__(self, targets, rate, reporte=None):  
        self.targets = targets       
        self.rate = rate               
        self.reporte = reporte        
        self.encontrados = []         
 

    def validate_target_format(self, target):  
        """  
        Valida el formato de la dirección IP o rango proporcionado.  
        Devuelve una lista de direcciones IP válidas.  
        """  
        try:  
            target_split = target.split(".")  
            if len(target_split) != 4:   
                return []  

            three_octets = '.'.join(target_split[:3])  
            last_octet = target_split[3]  

            if "-" in last_octet:  
                try:  
                    start, end = map(int, last_octet.split("-"))  
                    if start > end or start < 0 or end > 255:   
                        return []  
                    return [f"{three_octets}.{i}" for i in range(start, end + 1)]  
                except ValueError:  
                    return []  
            else:  
                try:  
                    if not 0 <= int(last_octet) <= 255:    
                        return []  
                    return [target]  
                except ValueError:    
                    return []  
        except Exception as e:   
            return []  

    def discovery_host(self, target):  
        """  
        Envía un ping (o escaneo con nmap) a la dirección IP proporcionada  
        para verificar si el host está activo.  
        """  
        nm = PortScanner()  
        try:    
            nm.scan(target, '1-1024', '-T' + str(self.rate))  
            if nm[target].get('status', {}).get('state') == 'up':  
                print(colored(f"\n\tHost: {target} UP", "green", attrs=["bold"]))   
                return target  
        except Exception as e:  
            pass 
        return None  

    def run_scan(self):  
        """  
        Ejecuta el proceso de validación de targets y escaneo concurrente.  
        """  
        ip_to_scan = []  
        for t in self.targets:  
            ip_list = self.validate_target_format(t)  
            ip_to_scan.extend(ip_list)  

        # Si no hay IPs válidas, finaliza.  
        if not ip_to_scan:  
            print(colored("[!] No hay direcciones IP válidas para escanear.", "red"))  
            sys.exit(1)  

        with ThreadPoolExecutor(max_workers=100) as executor:  
            for resultado in executor.map(self.discovery_host, ip_to_scan):  
                if resultado:  
                    self.encontrados.append(resultado)  

        if self.reporte:  
            self.save_to_file()  

        return self.encontrados  

    def save_to_file(self):  
        """  
        Guarda los resultados del escaneo en un archivo de texto.  
        """  
        try:  
            with open(self.reporte, 'w') as f:  
                f.write("=== Reporte de Escaneo de Red ===\n")  
                f.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")  
                f.write("=" * 35 + "\n\n")  

                if self.encontrados:  
                    f.write("Hosts Activos Encontrados:\n")  
                    for host in self.encontrados:  
                        f.write(f"- {host} UP\n")  
                else:  
                    f.write("No se encontraron hosts activos.\n")  

            print(colored(f"\n[+] Reporte de texto generado: {self.reporte}", "yellow"))  
        except Exception as e:  
            print(colored(f"\n[!] Error al guardar el archivo de texto: {e}", "red"))  
    
def close_program(sig, frame):  
    print(colored(f"\n[!] Hasta la próxima, amor", "red"))   
    sys.exit(1)  
 
signal.signal(signal.SIGINT, close_program)  

def parse_arguments():  
    """  
    Parsea los argumentos de la línea de comando.  
    """  
    parser = argparse.ArgumentParser(description="Descubre Hosts activos con (ICMP) y Nmap")  
    parser.add_argument('-t', '--target',   
                        required=True,   
                        dest="target",  
                        nargs='+',  
                        help="Ejemplo: -t 192.168.0.1 o -t 192.168.0.1-100")  
    parser.add_argument('--save',   
                        nargs='?',   
                        const='reporte.txt',   
                        default=None,  
                        help='Guarda los resultados en un archivo de texto. Opcionalmente, especifica el nombre.')  
    parser.add_argument('--rate',   
                        type=int,   
                        choices=range(0, 6),   
                        default=3,  
                        help="Controla la velocidad del escaneo (0 más lento, 5 más rápido). Default es 3.")  
    args = parser.parse_args()  
    return args.target, args.save, args.rate  

def main():  
    try:  
     
        banner = BannerManager()  
        banner.print_banner()  
  
        targets, reporte, rate = parse_arguments()  
 
        scanner = HostScanner(  
            targets=targets,  
            rate=rate,  
            reporte=reporte  
        )  
 
        resultados = scanner.run_scan()  

        print(colored(f"\n[*] Total de hosts encontrados: {len(resultados)}", "cyan"))  
        
    except Exception as e:  
        print(colored(f"[!] Ha ocurrido un error inesperado: {e}", "red"))  

if __name__ == "__main__":  
    main()
