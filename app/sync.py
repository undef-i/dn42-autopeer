import sqlite3
import os
import shutil
import hashlib
import subprocess
import logging
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def hash_file(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def execute_command(command):
    try:
        logger.info(f"Executing command: {command}")
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if result.stdout:
            logger.debug(f"Command output: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {command}")
        logger.error(f"Error: {e.stderr if e.stderr else str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error executing command: {command} - {e}")
        return False

def sync_config():
    logger.info("Starting configuration sync")
    
    config_dir = './config'
    wg_dir = os.path.join(config_dir, 'wireguard')
    bird_dir = os.path.join(config_dir, 'bird')
    
    os.makedirs(config_dir, exist_ok=True)
    
    previous_hashes_wg = {}
    previous_hashes_bird = {}
    current_hashes_wg = {}
    current_hashes_bird = {}
    
    hash_file_path = os.path.join(config_dir, 'hashes.txt')
    if os.path.exists(hash_file_path):
        with open(hash_file_path, 'r') as f:
            for line in f:
                key, file_hash = line.strip().split(',')
                if key.endswith('-wg'):
                    asn = key[:-3]
                    previous_hashes_wg[asn] = file_hash
                elif key.endswith('-bird'):
                    asn = key[:-5]
                    previous_hashes_bird[asn] = file_hash

    if os.path.exists(wg_dir):
        shutil.rmtree(wg_dir)
    os.makedirs(wg_dir)
    
    if os.path.exists(bird_dir):
        shutil.rmtree(bird_dir)
    os.makedirs(bird_dir)

    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT ASN, wireguard_public_key, endpoint, ipv6_link_local, ipv4, ipv6, multiprotocol_bgp, extended_next_hop FROM tunnels')
    tunnels = cursor.fetchall()
    
    logger.info(f"Processing {len(tunnels)} tunnels")
    
    for tunnel in tunnels:
        asn, wg_key, endpoint, ipv6ll, ipv4, ipv6, bgp_mp, bgp_enh = tunnel
        
        logger.info(f"Generating config for AS{asn}")
        
        if not Config.WIREGUARD_PRIVATE_KEY:
            logger.error("WIREGUARD_PRIVATE_KEY not configured")
            continue
        
        wg_config = f"""[Interface]
PrivateKey = {Config.WIREGUARD_PRIVATE_KEY}
ListenPort = {asn[-5:]}
"""
        
        if ipv4:
            wg_config += f"PostUp = ip address add dev %i {Config.WIREGUARD_SERVER_IPV4} peer {ipv4}\n"
        if ipv6:
            wg_config += f"PostUp = ip address add dev %i {Config.WIREGUARD_SERVER_IPV6} peer {ipv6}\n"
        if ipv6ll:
            wg_config += f"PostUp = ip address add dev %i {Config.WIREGUARD_SERVER_IPV6_LL} peer {ipv6ll}\n"

        wg_config += f"""
[Peer]
PublicKey = {wg_key}
"""
        if endpoint:
            wg_config += f"Endpoint = {endpoint}\n"
        wg_config += f"AllowedIPs = {Config.ALLOWED_IPS}\n"

        ipv6_neighbor = ipv6ll if ipv6ll else ipv6

        if not bgp_mp:
            bird_config = f"""protocol bgp bgp_{asn}_v4 from dnpeers {{
    neighbor {ipv4} as {asn};
    interface "{asn}";
    ipv4 {{}};
}}

protocol bgp bgp_{asn}_v6 from dnpeers {{
    neighbor {ipv6_neighbor} as {asn};
    interface "{asn}";
    ipv6 {{}};
}}
"""
        else:
            bird_config = f"""protocol bgp bgp_{asn} from dnpeers {{
    neighbor {ipv6_neighbor} as {asn};
    interface "{asn}";
    ipv4 {{
        extended next hop {'on' if bgp_enh else 'off'};
    }};
    ipv6 {{
        extended next hop off;
    }};
}}
"""

        wg_config_path = os.path.abspath(os.path.join(wg_dir, f'{asn}.conf'))
        with open(wg_config_path, 'w') as wg_file:
            wg_file.write(wg_config)

        current_hashes_wg[asn] = hash_file(wg_config_path)

        if asn not in previous_hashes_wg:
            logger.info(f"New tunnel for AS{asn}, bringing up WireGuard")
            execute_command(f'wg-quick down {wg_config_path}')
            execute_command(f'wg-quick up {wg_config_path}')
        elif previous_hashes_wg[asn] != current_hashes_wg[asn]:
            logger.info(f"Configuration changed for AS{asn}, restarting WireGuard")
            execute_command(f'wg-quick down {wg_config_path}')
            execute_command(f'wg-quick up {wg_config_path}')

        bird_config_path = os.path.abspath(os.path.join(bird_dir, f'{asn}.conf'))
        with open(bird_config_path, 'w') as bird_file:
            bird_file.write(bird_config)

        current_hashes_bird[asn] = hash_file(bird_config_path)

        if asn not in previous_hashes_bird:
            logger.info(f"New BGP config for AS{asn}, reloading BIRD")
            execute_command('birdc c')
        elif previous_hashes_bird[asn] != current_hashes_bird[asn]:
            logger.info(f"BGP config changed for AS{asn}, reloading BIRD")
            execute_command('birdc c')

    for asn in previous_hashes_wg:
        if asn not in current_hashes_wg:
            logger.info(f"Removing WireGuard config for AS{asn}")
            conf_path = os.path.abspath(os.path.join(wg_dir, f"{asn}.conf"))
            if os.path.exists(conf_path):
                execute_command(f'wg-quick down {conf_path}')
                os.remove(conf_path)

    for asn in previous_hashes_bird:
        if asn not in current_hashes_bird:
            logger.info(f"Removing BIRD config for AS{asn}")
            bird_conf_path = os.path.abspath(os.path.join(bird_dir, f'{asn}.conf'))
            if os.path.exists(bird_conf_path):
                os.remove(bird_conf_path)
            execute_command('birdc c')

    with open(hash_file_path, 'w') as f:
        for asn, file_hash in current_hashes_wg.items():
            f.write(f'{asn}-wg,{file_hash}\n')
        for asn, file_hash in current_hashes_bird.items():
            f.write(f'{asn}-bird,{file_hash}\n')

    execute_command('birdc c')

    conn.close()
    logger.info("Configuration sync completed successfully")

if __name__ == '__main__':
    sync_config()
