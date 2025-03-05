import requests

address = "37-458, Maisamh No 37, Somaiah Nagar, Jagathgiri Gutta, Hyderabad, Telangana 500037, India"
url = f"https://nominatim.openstreetmap.org/search?format=json&q={address}"

response = requests.get(url).json()
if response:
    print(response[0]['lat'], response[0]['lon'])
else:
    print("Invalid address. Could not fetch latitude and longitude.")
