export interface Country {
    id: string;
    isoCode: string;
    name: string;
}

export function calculateCountryId(name: string) {
    return name.replace(/[\s,.]/g, '_');
}

export const Countries: Country[] = [
    {
        "id": "Bangladesh",
        "isoCode": "BD",
        "name": "Bangladesh"
    },
    {
        "id": "Belgium",
        "isoCode": "BE",
        "name": "Belgium"
    },
    {
        "id": "Burkina_Faso",
        "isoCode": "BF",
        "name": "Burkina Faso"
    },
    {
        "id": "Bulgaria",
        "isoCode": "BG",
        "name": "Bulgaria"
    },
    {
        "id": "Bosnia_and_Herzegovina",
        "isoCode": "BA",
        "name": "Bosnia and Herzegovina"
    },
    {
        "id": "Barbados",
        "isoCode": "BB",
        "name": "Barbados"
    },
    {
        "id": "Wallis_and_Futuna",
        "isoCode": "WF",
        "name": "Wallis and Futuna"
    },
    {
        "id": "Saint_Barthelemy",
        "isoCode": "BL",
        "name": "Saint Barthelemy"
    },
    {
        "id": "Bermuda",
        "isoCode": "BM",
        "name": "Bermuda"
    },
    {
        "id": "Brunei",
        "isoCode": "BN",
        "name": "Brunei"
    },
    {
        "id": "Bolivia",
        "isoCode": "BO",
        "name": "Bolivia"
    },
    {
        "id": "Bahrain",
        "isoCode": "BH",
        "name": "Bahrain"
    },
    {
        "id": "Burundi",
        "isoCode": "BI",
        "name": "Burundi"
    },
    {
        "id": "Benin",
        "isoCode": "BJ",
        "name": "Benin"
    },
    {
        "id": "Bhutan",
        "isoCode": "BT",
        "name": "Bhutan"
    },
    {
        "id": "Jamaica",
        "isoCode": "JM",
        "name": "Jamaica"
    },
    {
        "id": "Bouvet_Island",
        "isoCode": "BV",
        "name": "Bouvet Island"
    },
    {
        "id": "Botswana",
        "isoCode": "BW",
        "name": "Botswana"
    },
    {
        "id": "Samoa",
        "isoCode": "WS",
        "name": "Samoa"
    },
    {
        "id": "Bonaire__Saint_Eustatius_and_Saba_",
        "isoCode": "BQ",
        "name": "Bonaire, Saint Eustatius and Saba "
    },
    {
        "id": "Brazil",
        "isoCode": "BR",
        "name": "Brazil"
    },
    {
        "id": "Bahamas",
        "isoCode": "BS",
        "name": "Bahamas"
    },
    {
        "id": "Jersey",
        "isoCode": "JE",
        "name": "Jersey"
    },
    {
        "id": "Belarus",
        "isoCode": "BY",
        "name": "Belarus"
    },
    {
        "id": "Belize",
        "isoCode": "BZ",
        "name": "Belize"
    },
    {
        "id": "Russia",
        "isoCode": "RU",
        "name": "Russia"
    },
    {
        "id": "Rwanda",
        "isoCode": "RW",
        "name": "Rwanda"
    },
    {
        "id": "Serbia",
        "isoCode": "RS",
        "name": "Serbia"
    },
    {
        "id": "East_Timor",
        "isoCode": "TL",
        "name": "East Timor"
    },
    {
        "id": "Reunion",
        "isoCode": "RE",
        "name": "Reunion"
    },
    {
        "id": "Turkmenistan",
        "isoCode": "TM",
        "name": "Turkmenistan"
    },
    {
        "id": "Tajikistan",
        "isoCode": "TJ",
        "name": "Tajikistan"
    },
    {
        "id": "Romania",
        "isoCode": "RO",
        "name": "Romania"
    },
    {
        "id": "Tokelau",
        "isoCode": "TK",
        "name": "Tokelau"
    },
    {
        "id": "Guinea-Bissau",
        "isoCode": "GW",
        "name": "Guinea-Bissau"
    },
    {
        "id": "Guam",
        "isoCode": "GU",
        "name": "Guam"
    },
    {
        "id": "Guatemala",
        "isoCode": "GT",
        "name": "Guatemala"
    },
    {
        "id": "South_Georgia_and_the_South_Sandwich_Islands",
        "isoCode": "GS",
        "name": "South Georgia and the South Sandwich Islands"
    },
    {
        "id": "Greece",
        "isoCode": "GR",
        "name": "Greece"
    },
    {
        "id": "Equatorial_Guinea",
        "isoCode": "GQ",
        "name": "Equatorial Guinea"
    },
    {
        "id": "Guadeloupe",
        "isoCode": "GP",
        "name": "Guadeloupe"
    },
    {
        "id": "Japan",
        "isoCode": "JP",
        "name": "Japan"
    },
    {
        "id": "Guyana",
        "isoCode": "GY",
        "name": "Guyana"
    },
    {
        "id": "Guernsey",
        "isoCode": "GG",
        "name": "Guernsey"
    },
    {
        "id": "French_Guiana",
        "isoCode": "GF",
        "name": "French Guiana"
    },
    {
        "id": "Georgia",
        "isoCode": "GE",
        "name": "Georgia"
    },
    {
        "id": "Grenada",
        "isoCode": "GD",
        "name": "Grenada"
    },
    {
        "id": "United_Kingdom",
        "isoCode": "GB",
        "name": "United Kingdom"
    },
    {
        "id": "Gabon",
        "isoCode": "GA",
        "name": "Gabon"
    },
    {
        "id": "El_Salvador",
        "isoCode": "SV",
        "name": "El Salvador"
    },
    {
        "id": "Guinea",
        "isoCode": "GN",
        "name": "Guinea"
    },
    {
        "id": "Gambia",
        "isoCode": "GM",
        "name": "Gambia"
    },
    {
        "id": "Greenland",
        "isoCode": "GL",
        "name": "Greenland"
    },
    {
        "id": "Gibraltar",
        "isoCode": "GI",
        "name": "Gibraltar"
    },
    {
        "id": "Ghana",
        "isoCode": "GH",
        "name": "Ghana"
    },
    {
        "id": "Oman",
        "isoCode": "OM",
        "name": "Oman"
    },
    {
        "id": "Tunisia",
        "isoCode": "TN",
        "name": "Tunisia"
    },
    {
        "id": "Jordan",
        "isoCode": "JO",
        "name": "Jordan"
    },
    {
        "id": "Croatia",
        "isoCode": "HR",
        "name": "Croatia"
    },
    {
        "id": "Haiti",
        "isoCode": "HT",
        "name": "Haiti"
    },
    {
        "id": "Hungary",
        "isoCode": "HU",
        "name": "Hungary"
    },
    {
        "id": "Hong_Kong",
        "isoCode": "HK",
        "name": "Hong Kong"
    },
    {
        "id": "Honduras",
        "isoCode": "HN",
        "name": "Honduras"
    },
    {
        "id": "Heard_Island_and_McDonald_Islands",
        "isoCode": "HM",
        "name": "Heard Island and McDonald Islands"
    },
    {
        "id": "Venezuela",
        "isoCode": "VE",
        "name": "Venezuela"
    },
    {
        "id": "Puerto_Rico",
        "isoCode": "PR",
        "name": "Puerto Rico"
    },
    {
        "id": "Palestinian_Territory",
        "isoCode": "PS",
        "name": "Palestinian Territory"
    },
    {
        "id": "Palau",
        "isoCode": "PW",
        "name": "Palau"
    },
    {
        "id": "Portugal",
        "isoCode": "PT",
        "name": "Portugal"
    },
    {
        "id": "Svalbard_and_Jan_Mayen",
        "isoCode": "SJ",
        "name": "Svalbard and Jan Mayen"
    },
    {
        "id": "Paraguay",
        "isoCode": "PY",
        "name": "Paraguay"
    },
    {
        "id": "Iraq",
        "isoCode": "IQ",
        "name": "Iraq"
    },
    {
        "id": "Panama",
        "isoCode": "PA",
        "name": "Panama"
    },
    {
        "id": "French_Polynesia",
        "isoCode": "PF",
        "name": "French Polynesia"
    },
    {
        "id": "Papua_New_Guinea",
        "isoCode": "PG",
        "name": "Papua New Guinea"
    },
    {
        "id": "Peru",
        "isoCode": "PE",
        "name": "Peru"
    },
    {
        "id": "Pakistan",
        "isoCode": "PK",
        "name": "Pakistan"
    },
    {
        "id": "Philippines",
        "isoCode": "PH",
        "name": "Philippines"
    },
    {
        "id": "Pitcairn",
        "isoCode": "PN",
        "name": "Pitcairn"
    },
    {
        "id": "Poland",
        "isoCode": "PL",
        "name": "Poland"
    },
    {
        "id": "Saint_Pierre_and_Miquelon",
        "isoCode": "PM",
        "name": "Saint Pierre and Miquelon"
    },
    {
        "id": "Zambia",
        "isoCode": "ZM",
        "name": "Zambia"
    },
    {
        "id": "Western_Sahara",
        "isoCode": "EH",
        "name": "Western Sahara"
    },
    {
        "id": "Estonia",
        "isoCode": "EE",
        "name": "Estonia"
    },
    {
        "id": "Egypt",
        "isoCode": "EG",
        "name": "Egypt"
    },
    {
        "id": "South_Africa",
        "isoCode": "ZA",
        "name": "South Africa"
    },
    {
        "id": "Ecuador",
        "isoCode": "EC",
        "name": "Ecuador"
    },
    {
        "id": "Italy",
        "isoCode": "IT",
        "name": "Italy"
    },
    {
        "id": "Vietnam",
        "isoCode": "VN",
        "name": "Vietnam"
    },
    {
        "id": "Solomon_Islands",
        "isoCode": "SB",
        "name": "Solomon Islands"
    },
    {
        "id": "Ethiopia",
        "isoCode": "ET",
        "name": "Ethiopia"
    },
    {
        "id": "Somalia",
        "isoCode": "SO",
        "name": "Somalia"
    },
    {
        "id": "Zimbabwe",
        "isoCode": "ZW",
        "name": "Zimbabwe"
    },
    {
        "id": "Saudi_Arabia",
        "isoCode": "SA",
        "name": "Saudi Arabia"
    },
    {
        "id": "Spain",
        "isoCode": "ES",
        "name": "Spain"
    },
    {
        "id": "Eritrea",
        "isoCode": "ER",
        "name": "Eritrea"
    },
    {
        "id": "Montenegro",
        "isoCode": "ME",
        "name": "Montenegro"
    },
    {
        "id": "Moldova",
        "isoCode": "MD",
        "name": "Moldova"
    },
    {
        "id": "Madagascar",
        "isoCode": "MG",
        "name": "Madagascar"
    },
    {
        "id": "Saint_Martin",
        "isoCode": "MF",
        "name": "Saint Martin"
    },
    {
        "id": "Morocco",
        "isoCode": "MA",
        "name": "Morocco"
    },
    {
        "id": "Monaco",
        "isoCode": "MC",
        "name": "Monaco"
    },
    {
        "id": "Uzbekistan",
        "isoCode": "UZ",
        "name": "Uzbekistan"
    },
    {
        "id": "Myanmar",
        "isoCode": "MM",
        "name": "Myanmar"
    },
    {
        "id": "Mali",
        "isoCode": "ML",
        "name": "Mali"
    },
    {
        "id": "Macao",
        "isoCode": "MO",
        "name": "Macao"
    },
    {
        "id": "Mongolia",
        "isoCode": "MN",
        "name": "Mongolia"
    },
    {
        "id": "Marshall_Islands",
        "isoCode": "MH",
        "name": "Marshall Islands"
    },
    {
        "id": "Macedonia",
        "isoCode": "MK",
        "name": "Macedonia"
    },
    {
        "id": "Mauritius",
        "isoCode": "MU",
        "name": "Mauritius"
    },
    {
        "id": "Malta",
        "isoCode": "MT",
        "name": "Malta"
    },
    {
        "id": "Malawi",
        "isoCode": "MW",
        "name": "Malawi"
    },
    {
        "id": "Maldives",
        "isoCode": "MV",
        "name": "Maldives"
    },
    {
        "id": "Martinique",
        "isoCode": "MQ",
        "name": "Martinique"
    },
    {
        "id": "Northern_Mariana_Islands",
        "isoCode": "MP",
        "name": "Northern Mariana Islands"
    },
    {
        "id": "Montserrat",
        "isoCode": "MS",
        "name": "Montserrat"
    },
    {
        "id": "Mauritania",
        "isoCode": "MR",
        "name": "Mauritania"
    },
    {
        "id": "Isle_of_Man",
        "isoCode": "IM",
        "name": "Isle of Man"
    },
    {
        "id": "Uganda",
        "isoCode": "UG",
        "name": "Uganda"
    },
    {
        "id": "Tanzania",
        "isoCode": "TZ",
        "name": "Tanzania"
    },
    {
        "id": "Malaysia",
        "isoCode": "MY",
        "name": "Malaysia"
    },
    {
        "id": "Mexico",
        "isoCode": "MX",
        "name": "Mexico"
    },
    {
        "id": "Israel",
        "isoCode": "IL",
        "name": "Israel"
    },
    {
        "id": "France",
        "isoCode": "FR",
        "name": "France"
    },
    {
        "id": "British_Indian_Ocean_Territory",
        "isoCode": "IO",
        "name": "British Indian Ocean Territory"
    },
    {
        "id": "Saint_Helena",
        "isoCode": "SH",
        "name": "Saint Helena"
    },
    {
        "id": "Finland",
        "isoCode": "FI",
        "name": "Finland"
    },
    {
        "id": "Fiji",
        "isoCode": "FJ",
        "name": "Fiji"
    },
    {
        "id": "Falkland_Islands",
        "isoCode": "FK",
        "name": "Falkland Islands"
    },
    {
        "id": "Micronesia",
        "isoCode": "FM",
        "name": "Micronesia"
    },
    {
        "id": "Faroe_Islands",
        "isoCode": "FO",
        "name": "Faroe Islands"
    },
    {
        "id": "Nicaragua",
        "isoCode": "NI",
        "name": "Nicaragua"
    },
    {
        "id": "Netherlands",
        "isoCode": "NL",
        "name": "Netherlands"
    },
    {
        "id": "Norway",
        "isoCode": "NO",
        "name": "Norway"
    },
    {
        "id": "Namibia",
        "isoCode": "NA",
        "name": "Namibia"
    },
    {
        "id": "Vanuatu",
        "isoCode": "VU",
        "name": "Vanuatu"
    },
    {
        "id": "New_Caledonia",
        "isoCode": "NC",
        "name": "New Caledonia"
    },
    {
        "id": "Niger",
        "isoCode": "NE",
        "name": "Niger"
    },
    {
        "id": "Norfolk_Island",
        "isoCode": "NF",
        "name": "Norfolk Island"
    },
    {
        "id": "Nigeria",
        "isoCode": "NG",
        "name": "Nigeria"
    },
    {
        "id": "New_Zealand",
        "isoCode": "NZ",
        "name": "New Zealand"
    },
    {
        "id": "Nepal",
        "isoCode": "NP",
        "name": "Nepal"
    },
    {
        "id": "Nauru",
        "isoCode": "NR",
        "name": "Nauru"
    },
    {
        "id": "Niue",
        "isoCode": "NU",
        "name": "Niue"
    },
    {
        "id": "Cook_Islands",
        "isoCode": "CK",
        "name": "Cook Islands"
    },
    {
        "id": "Kosovo",
        "isoCode": "XK",
        "name": "Kosovo"
    },
    {
        "id": "Ivory_Coast",
        "isoCode": "CI",
        "name": "Ivory Coast"
    },
    {
        "id": "Switzerland",
        "isoCode": "CH",
        "name": "Switzerland"
    },
    {
        "id": "Colombia",
        "isoCode": "CO",
        "name": "Colombia"
    },
    {
        "id": "China",
        "isoCode": "CN",
        "name": "China"
    },
    {
        "id": "Cameroon",
        "isoCode": "CM",
        "name": "Cameroon"
    },
    {
        "id": "Chile",
        "isoCode": "CL",
        "name": "Chile"
    },
    {
        "id": "Cocos_Islands",
        "isoCode": "CC",
        "name": "Cocos Islands"
    },
    {
        "id": "Canada",
        "isoCode": "CA",
        "name": "Canada"
    },
    {
        "id": "Republic_of_the_Congo",
        "isoCode": "CG",
        "name": "Republic of the Congo"
    },
    {
        "id": "Central_African_Republic",
        "isoCode": "CF",
        "name": "Central African Republic"
    },
    {
        "id": "Democratic_Republic_of_the_Congo",
        "isoCode": "CD",
        "name": "Democratic Republic of the Congo"
    },
    {
        "id": "Czech_Republic",
        "isoCode": "CZ",
        "name": "Czech Republic"
    },
    {
        "id": "Cyprus",
        "isoCode": "CY",
        "name": "Cyprus"
    },
    {
        "id": "Christmas_Island",
        "isoCode": "CX",
        "name": "Christmas Island"
    },
    {
        "id": "Costa_Rica",
        "isoCode": "CR",
        "name": "Costa Rica"
    },
    {
        "id": "Curacao",
        "isoCode": "CW",
        "name": "Curacao"
    },
    {
        "id": "Cape_Verde",
        "isoCode": "CV",
        "name": "Cape Verde"
    },
    {
        "id": "Cuba",
        "isoCode": "CU",
        "name": "Cuba"
    },
    {
        "id": "Swaziland",
        "isoCode": "SZ",
        "name": "Swaziland"
    },
    {
        "id": "Syria",
        "isoCode": "SY",
        "name": "Syria"
    },
    {
        "id": "Sint_Maarten",
        "isoCode": "SX",
        "name": "Sint Maarten"
    },
    {
        "id": "Kyrgyzstan",
        "isoCode": "KG",
        "name": "Kyrgyzstan"
    },
    {
        "id": "Kenya",
        "isoCode": "KE",
        "name": "Kenya"
    },
    {
        "id": "South_Sudan",
        "isoCode": "SS",
        "name": "South Sudan"
    },
    {
        "id": "Suriname",
        "isoCode": "SR",
        "name": "Suriname"
    },
    {
        "id": "Kiribati",
        "isoCode": "KI",
        "name": "Kiribati"
    },
    {
        "id": "Cambodia",
        "isoCode": "KH",
        "name": "Cambodia"
    },
    {
        "id": "Saint_Kitts_and_Nevis",
        "isoCode": "KN",
        "name": "Saint Kitts and Nevis"
    },
    {
        "id": "Comoros",
        "isoCode": "KM",
        "name": "Comoros"
    },
    {
        "id": "Sao_Tome_and_Principe",
        "isoCode": "ST",
        "name": "Sao Tome and Principe"
    },
    {
        "id": "Slovakia",
        "isoCode": "SK",
        "name": "Slovakia"
    },
    {
        "id": "South_Korea",
        "isoCode": "KR",
        "name": "South Korea"
    },
    {
        "id": "Slovenia",
        "isoCode": "SI",
        "name": "Slovenia"
    },
    {
        "id": "North_Korea",
        "isoCode": "KP",
        "name": "North Korea"
    },
    {
        "id": "Kuwait",
        "isoCode": "KW",
        "name": "Kuwait"
    },
    {
        "id": "Senegal",
        "isoCode": "SN",
        "name": "Senegal"
    },
    {
        "id": "San_Marino",
        "isoCode": "SM",
        "name": "San Marino"
    },
    {
        "id": "Sierra_Leone",
        "isoCode": "SL",
        "name": "Sierra Leone"
    },
    {
        "id": "Seychelles",
        "isoCode": "SC",
        "name": "Seychelles"
    },
    {
        "id": "Kazakhstan",
        "isoCode": "KZ",
        "name": "Kazakhstan"
    },
    {
        "id": "Cayman_Islands",
        "isoCode": "KY",
        "name": "Cayman Islands"
    },
    {
        "id": "Singapore",
        "isoCode": "SG",
        "name": "Singapore"
    },
    {
        "id": "Sweden",
        "isoCode": "SE",
        "name": "Sweden"
    },
    {
        "id": "Sudan",
        "isoCode": "SD",
        "name": "Sudan"
    },
    {
        "id": "Dominican_Republic",
        "isoCode": "DO",
        "name": "Dominican Republic"
    },
    {
        "id": "Dominica",
        "isoCode": "DM",
        "name": "Dominica"
    },
    {
        "id": "Djibouti",
        "isoCode": "DJ",
        "name": "Djibouti"
    },
    {
        "id": "Denmark",
        "isoCode": "DK",
        "name": "Denmark"
    },
    {
        "id": "British_Virgin_Islands",
        "isoCode": "VG",
        "name": "British Virgin Islands"
    },
    {
        "id": "Germany",
        "isoCode": "DE",
        "name": "Germany"
    },
    {
        "id": "Yemen",
        "isoCode": "YE",
        "name": "Yemen"
    },
    {
        "id": "Algeria",
        "isoCode": "DZ",
        "name": "Algeria"
    },
    {
        "id": "United_States",
        "isoCode": "US",
        "name": "United States"
    },
    {
        "id": "Uruguay",
        "isoCode": "UY",
        "name": "Uruguay"
    },
    {
        "id": "Mayotte",
        "isoCode": "YT",
        "name": "Mayotte"
    },
    {
        "id": "United_States_Minor_Outlying_Islands",
        "isoCode": "UM",
        "name": "United States Minor Outlying Islands"
    },
    {
        "id": "Lebanon",
        "isoCode": "LB",
        "name": "Lebanon"
    },
    {
        "id": "Saint_Lucia",
        "isoCode": "LC",
        "name": "Saint Lucia"
    },
    {
        "id": "Laos",
        "isoCode": "LA",
        "name": "Laos"
    },
    {
        "id": "Tuvalu",
        "isoCode": "TV",
        "name": "Tuvalu"
    },
    {
        "id": "Taiwan",
        "isoCode": "TW",
        "name": "Taiwan"
    },
    {
        "id": "Trinidad_and_Tobago",
        "isoCode": "TT",
        "name": "Trinidad and Tobago"
    },
    {
        "id": "Turkey",
        "isoCode": "TR",
        "name": "Turkey"
    },
    {
        "id": "Sri_Lanka",
        "isoCode": "LK",
        "name": "Sri Lanka"
    },
    {
        "id": "Liechtenstein",
        "isoCode": "LI",
        "name": "Liechtenstein"
    },
    {
        "id": "Latvia",
        "isoCode": "LV",
        "name": "Latvia"
    },
    {
        "id": "Tonga",
        "isoCode": "TO",
        "name": "Tonga"
    },
    {
        "id": "Lithuania",
        "isoCode": "LT",
        "name": "Lithuania"
    },
    {
        "id": "Luxembourg",
        "isoCode": "LU",
        "name": "Luxembourg"
    },
    {
        "id": "Liberia",
        "isoCode": "LR",
        "name": "Liberia"
    },
    {
        "id": "Lesotho",
        "isoCode": "LS",
        "name": "Lesotho"
    },
    {
        "id": "Thailand",
        "isoCode": "TH",
        "name": "Thailand"
    },
    {
        "id": "French_Southern_Territories",
        "isoCode": "TF",
        "name": "French Southern Territories"
    },
    {
        "id": "Togo",
        "isoCode": "TG",
        "name": "Togo"
    },
    {
        "id": "Chad",
        "isoCode": "TD",
        "name": "Chad"
    },
    {
        "id": "Turks_and_Caicos_Islands",
        "isoCode": "TC",
        "name": "Turks and Caicos Islands"
    },
    {
        "id": "Libya",
        "isoCode": "LY",
        "name": "Libya"
    },
    {
        "id": "Vatican",
        "isoCode": "VA",
        "name": "Vatican"
    },
    {
        "id": "Saint_Vincent_and_the_Grenadines",
        "isoCode": "VC",
        "name": "Saint Vincent and the Grenadines"
    },
    {
        "id": "United_Arab_Emirates",
        "isoCode": "AE",
        "name": "United Arab Emirates"
    },
    {
        "id": "Andorra",
        "isoCode": "AD",
        "name": "Andorra"
    },
    {
        "id": "Antigua_and_Barbuda",
        "isoCode": "AG",
        "name": "Antigua and Barbuda"
    },
    {
        "id": "Afghanistan",
        "isoCode": "AF",
        "name": "Afghanistan"
    },
    {
        "id": "Anguilla",
        "isoCode": "AI",
        "name": "Anguilla"
    },
    {
        "id": "U_S__Virgin_Islands",
        "isoCode": "VI",
        "name": "U.S. Virgin Islands"
    },
    {
        "id": "Iceland",
        "isoCode": "IS",
        "name": "Iceland"
    },
    {
        "id": "Iran",
        "isoCode": "IR",
        "name": "Iran"
    },
    {
        "id": "Armenia",
        "isoCode": "AM",
        "name": "Armenia"
    },
    {
        "id": "Albania",
        "isoCode": "AL",
        "name": "Albania"
    },
    {
        "id": "Angola",
        "isoCode": "AO",
        "name": "Angola"
    },
    {
        "id": "Antarctica",
        "isoCode": "AQ",
        "name": "Antarctica"
    },
    {
        "id": "American_Samoa",
        "isoCode": "AS",
        "name": "American Samoa"
    },
    {
        "id": "Argentina",
        "isoCode": "AR",
        "name": "Argentina"
    },
    {
        "id": "Australia",
        "isoCode": "AU",
        "name": "Australia"
    },
    {
        "id": "Austria",
        "isoCode": "AT",
        "name": "Austria"
    },
    {
        "id": "Aruba",
        "isoCode": "AW",
        "name": "Aruba"
    },
    {
        "id": "India",
        "isoCode": "IN",
        "name": "India"
    },
    {
        "id": "Aland_Islands",
        "isoCode": "AX",
        "name": "Aland Islands"
    },
    {
        "id": "Azerbaijan",
        "isoCode": "AZ",
        "name": "Azerbaijan"
    },
    {
        "id": "Ireland",
        "isoCode": "IE",
        "name": "Ireland"
    },
    {
        "id": "Indonesia",
        "isoCode": "ID",
        "name": "Indonesia"
    },
    {
        "id": "Ukraine",
        "isoCode": "UA",
        "name": "Ukraine"
    },
    {
        "id": "Qatar",
        "isoCode": "QA",
        "name": "Qatar"
    },
    {
        "id": "Mozambique",
        "isoCode": "MZ",
        "name": "Mozambique"
    }
]