from scone_cli import fspf

(key, tag) = fspf.create_empty_volume_encr("volume.fspf")
print("Key: " + ''.join(format(x, '02x') for x in key))
print("Tag: " + ''.join(format(x, '02x') for x in tag))
