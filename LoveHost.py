#!/usr/bin/python  
import argparse  
from termcolor import colored  
import subprocess  
import signal  
import sys  
from concurrent.futures import ThreadPoolExecutor  
from pyfiglet import Figlet  
from datetime import datetime  
from nmap import PortScanner  

def print_figlet(text):  
    """  
    Imprime en la pantalla el texto proporcionado con un diseño ASCII.  
    """  
    figlet = Figlet(font='banner3')  # Cambiado a 'standard' para evitar errores  
    ascii_art = figlet.renderText(text)  
    try:  
        lolcat_process = subprocess.Popen(['lolcat'], stdin=subprocess.PIPE)  
        lolcat_process.communicate(input=ascii_art.encode())  
    except FileNotFoundError:  
        print(ascii_art)  

def printed():  
    """  
    Imprime el banner y la información inicial del programa.  
    """  
    print_figlet("LOVEHOST")  
    print("\n@puerto4444")  
    print("-" * 30)  

def close_program(sig, frame):  
    """  
    Maneja la interrupción del programa al presionar Ctrl+C.  
    """  
    print(colored(f"\n[!] Hasta la próxima, amor", "red"))  
    sys.exit(1)  

signal.signal(signal.SIGINT, close_program)  

def Arg_parse():  
    """  
    Parsea los argumentos de la línea de comando.  
    """  
    parser = argparse.ArgumentParser(description="Descubre Hosts activos con (ICMP) y Nmap")  
    parser.add_argument('-t', '--target', required=True, dest="target",  
                        help="Ex: -t 192.168.0.1 o -t 192.168.0.1-100")  
    parser.add_argument('--save', nargs='?', const='reporte.txt', default=None,  
                        help='Guarda los resultados en un archivo de texto. Opcionalmente, especifica el nombre del archivo.')  
    parser.add_argument('--rate', type=int, choices=range(0, 6), default=3,  
                        help="Controla la velocidad del escaneo (0 más lento, 5 más rápido). Default es 3.")  
    args = parser.parse_args()  
    return args.target, args.save, args.rate  

def Valid_target(target):  
    """  
    Valida el formato de la dirección IP o rango proporcionado.  
    """  
    target_split = target.split(".")  
    if len(target_split) != 4:  
        print(colored(f"\n[!] Formato de IP inválido: {target}\n", "red"))  
        return []  

    three_octets = '.'.join(target_split[:3])  
    last_octet = target_split[3]  

    if "-" in last_octet:  
        try:  
            start, end = map(int, last_octet.split("-"))  
            if start > end or start < 0 or end > 255:  
                print(colored(f"\n[!] Rango de IP inválido: {target}\n", "red"))  
                return []  
            return [f"{three_octets}.{i}" for i in range(start, end + 1)]  
        except ValueError:  
            print(colored(f"\n[!] Formato de rango de IP inválido: {target}\n", "red"))  
            return []  
    else:  
        try:  
            if not 0 <= int(last_octet) <= 255:  
                print(colored(f"\n[!] Octeto final fuera de rango: {target}\n", "red"))  
                return []  
            return [target]  
        except ValueError:  
            print(colored(f"\n[!] Octeto final no es un número: {target}\n", "red"))  
            return []  

def descovery_host(target, rate):  
    """  
    Envía un ping a la dirección IP proporcionada para verificar si el host está activo.  
    """  
    nm = PortScanner()  
    try:   
        nm.scan(target, '1-1024', '-T' + str(rate))  
        if nm[target].get('status', {}).get('state') == 'up':  
            print(colored(f"\n\tHost: {target} UP", "green", attrs=["bold"]))  
            return target  
    except Exception as e:  
        pass  
    return None  

def guardar_resultados_txt(resultados, nombre_archivo='reporte.txt'):  
    """  
    Guarda los resultados del escaneo en un archivo de texto.  
    """  
    try:  
        with open(nombre_archivo, 'w') as f:  
            f.write("=== Reporte de Escaneo de Red ===\n")  
            f.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")  
            f.write("=" * 35 + "\n\n")  
            
            if resultados:  
                f.write("Hosts Activos Encontrados:\n")  
                for host in resultados:  
                    f.write(f"- {host} UP\n")  
            else:  
                f.write("No se encontraron hosts activos.\n")  
        print(colored(f"\n[+] Reporte de texto generado: {nombre_archivo}", "yellow"))  
    except Exception as e:  
        print(colored(f"\n[!] Error al guardar el archivo de texto: {e}", "red"))  

def main():  
    """  
    La función principal del programa.  
    """  
    printed()  
    target, generar_txt, rate = Arg_parse()  
    targets = Valid_target(target)  

    if not targets:  
        print(colored("[!] No hay direcciones IP válidas para escanear.", "red"))  
        sys.exit(1)  

    resultados = []  
    with ThreadPoolExecutor(max_workers=100) as executor:  
        for resultado in executor.map(lambda x: descovery_host(x, rate), targets):  
            if resultado:  
                resultados.append(resultado)  

    if generar_txt:  
        guardar_resultados_txt(resultados, generar_txt)  

if __name__ == "__main__":  
    main()
