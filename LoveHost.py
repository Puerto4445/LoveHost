#!/usr/bin/python  
import argparse  
from termcolor import colored  
import subprocess  
import signal  
import sys  
from concurrent.futures import ThreadPoolExecutor  
from pyfiglet import Figlet  
from datetime import datetime  
from ratelimiter import RateLimiter  

def print_figlet(text):  
    """  
    Imprime en la pantalla el texto proporcionado con un diseño ASCII.  

    Args:  
        text (str): El texto a imprimir con el diseño ASCII.  

    Returns:  
        None  
    """  
    figlet = Figlet(font='banner3')  
    ascii_art = figlet.renderText(text)  
    try:  
        lolcat_process = subprocess.Popen(['lolcat'], stdin=subprocess.PIPE)  
        lolcat_process.communicate(input=ascii_art.encode())  
    except FileNotFoundError:  
        print(ascii_art)  

def printed():  
    """  
    Imprime el banner y la información inicial del programa.  

    Returns:  
        None  
    """  
    print_figlet("LOVEHOST")  
    print("\n@puerto4444")  
    print("-" * 30)  

def close_program(sig, frame):  
    """  
    Maneja la interrupción del programa al presionar Ctrl+C.  

    Args:  
        sig (signal): El signal de interrupción.  
        frame (frame): El frame actual del programa.  

    Returns:  
        None  
    """  
    print(colored(f"\n[!] Hasta la próxima, amor", "red"))  
    sys.exit(1)  

signal.signal(signal.SIGINT, close_program)  

def Arg_parse():  
    """  
    Parsea los argumentos de la línea de comando.  

    Returns:  
        Namespace: Objeto que contiene los argumentos parseados.  
    """  
    parser = argparse.ArgumentParser(description="Descubre Hosts activos con (ICMP)")  
    parser.add_argument('-t', '--target', required=True, dest="target",  
                        help="Ex: -t 192.168.0.1 o -t 192.168.0.1-100")  
    parser.add_argument('--save', nargs='?', const='reporte.txt', default=None,  
                        help='Guarda los resultados en un archivo de texto. Opcionalmente, especifica el nombre del archivo.')  
    parser.add_argument('--rate', type=int, default=100,  
                        help='Número máximo de solicitudes por segundo (default: 100)')  
    args = parser.parse_args()  
    return args  

def Valid_target(target):  
    """  
    Valida el formato de la dirección IP o rango proporcionado.  

    Args:  
        target (str): La dirección IP o rango a validar.  

    Returns:  
        list: Una lista de direcciones IP válidas.  
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

def rate_limited_discovery(rate):  
    """  
    Crea una función de descubrimiento con límite de tasa.    
    Returns:  
        function: Función de descubrimiento con límite de tasa.  
    """  
    rate_limiter = RateLimiter(max_calls=rate, period=1)  

    @rate_limiter  
    def limited_discovery(target):  
        try:  
            discovery = subprocess.run(["ping", "-c", "1", target], timeout=1, stdout=subprocess.DEVNULL)  
            if discovery.returncode == 0:  
                print(colored(f"\n\tHost: {target} UP", "green", attrs=["bold"]))  
                return target  
        except subprocess.TimeoutExpired:  
            pass  
        return None  

    return limited_discovery  

def guardar_resultados_txt(resultados, nombre_archivo='reporte.txt'):  
    """  
    Guarda los resultados del escaneo en un archivo de texto.  

    Args:  
        resultados (list): Lista de direcciones IP activas.  
        nombre_archivo (str): Nombre del archivo de salida.  

    Returns:  
        None  
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

    Returns:  
        None  
    """  
    printed()  
    args = Arg_parse()  
    targets = Valid_target(args.target)  
    
    if not targets:  
        print(colored("[!] No hay direcciones IP válidas para escanear.", "red"))  
        sys.exit(1)  
      
    discovery_func = rate_limited_discovery(args.rate)  
    
    print(colored(f"\n[+] Iniciando escaneo con tasa máxima de {args.rate} solicitudes/segundo", "yellow"))  
    
    resultados = []  
    with ThreadPoolExecutor(max_workers=min(100, args.rate)) as executor:  
        for resultado in executor.map(discovery_func, targets):  
            if resultado:  
                resultados.append(resultado)  
    
    if args.save:  
        guardar_resultados_txt(resultados, args.save)  

if __name__ == "__main__":  
    main()
