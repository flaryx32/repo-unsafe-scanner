# GitHub Repository Scanner

This repository aims to scan GitHub repositories for known encryption tools, suspicious code, and executables using VirusTotal and OpenAI APIs.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have Python 3.6 or later installed.
- You have an OpenAI API key.(optional)
- You have a VirusTotal API key.(optional)
- You have a GitHub API key (optional).

## Setup

1. Clone this repository:

    ```sh
    git clone https://github.com/flaryx32/repo-unsafe-scanner.git
    cd your-repo
    ```

2. Install the required libraries:

    ```sh
    pip install -r requirements.txt
    ```

3. Modify `config.json` file and add your API keys:

    ```json
    {
        "github_api_key": "your_github_api_key",
        "virustotal_api_key": "your_virustotal_api_key",
        "openai_api_key": "your_openai_api_key"
    }
    ```

## Usage

To run the scanner:

```sh
python main.py
```

Follow the prompts to enter the GitHub repository URL you wish to scan.

## License

The code in this repository is made available under a custom license that allows free private usage but prohibits modifications, commercial usage, and redistribution without permission. All rights to the code are owned by [@flaryx32](https://github.com/flaryx32).

## Contributing

Contributions are welcome! To contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for each significant change.
3. Push your changes and open a pull request.

Please ensure your pull request adheres to the following guidelines:

- Include a clear description of your changes.
- Ensure that your changes do not break existing functionality.
 
## Future Plans

- [x] AI Scanner
- [x] VirusTotal Executable Scanner
- [ ] More...

If you have any suggestions or feature requests, please open an issue or submit a pull request.

## Missing Anything?

If you notice anything missing or incorrect, feel free to open an issue or submit a pull request.
