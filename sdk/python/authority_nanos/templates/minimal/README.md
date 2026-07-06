# {{PROJECT_NAME}}

A minimal starter program that runs under Authority, demonstrating basic heap operations.

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run in simulation mode:
   ```bash
   python agent.py
   ```

3. Run under the Authority kernel:
   ```bash
   authority run agent.py --policy policy.json
   ```

## Project Structure

- `agent.py` - Main program code with heap operations
- `policy.json` - Security policy defining the allowed capabilities
- `requirements.txt` - Python dependencies

## Policy

The policy file (`policy.json`) defines what the program is allowed to do:
- Heap operations (alloc, read, write, delete)
- No network access
- No filesystem access

## Learn More

- [Authority Documentation](https://mbhatt1.github.io/authority)
- [Policy Format Reference](https://mbhatt1.github.io/authority/policy/)
- [API Reference](https://mbhatt1.github.io/authority/api/)
