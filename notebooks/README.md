# Authority Jupyter Notebooks

Interactive tutorials for learning the Authority Python SDK - writing programs
that run under Authority.

## Prerequisites

- Python 3.8 or later
- Jupyter Notebook or JupyterLab

## Installation

1. Install Jupyter:
   ```bash
   pip install jupyter
   ```

2. Install the Authority SDK:
   ```bash
   pip install authority-nanos
   ```

   Or install from source:
   ```bash
   cd sdk/python
   pip install -e .
   ```

## Running the Notebooks

Start Jupyter:
```bash
jupyter notebook
```

Or with JupyterLab:
```bash
jupyter lab
```

Then navigate to the `notebooks/` directory and open any notebook.

## Notebooks

### 01_getting_started.ipynb

**Introduction to Authority**

- What Authority is
- Installing the SDK
- Hello World example
- Basic heap operations (alloc, read, write, delete)

Start here if you are new to Authority.

### 02_authorization.ipynb

**Capability-Based Authorization**

- How capability-based authorization works
- Creating and checking capabilities
- Policy configuration in simulation mode
- Handling authorization denials
- Pattern-based policies (advanced)

Learn how to secure a program with fine-grained access control.

### 03_building_agents.ipynb

**Building a Program: Tools and Outbound Requests**

- Structuring a program that runs under Authority
- Executing sandboxed WASM tools through the kernel
- Issuing capability-gated outbound requests
- Building a work loop
- Managing program state in the typed heap
- Handling policy constraints and denials

Build a program whose tool calls and outbound requests are mediated by the kernel.

### 04_langchain_integration.ipynb

**Integrating an External Library**

- Using a third-party library from a program running under Authority
- Routing the library's outbound requests through the kernel
- Exposing tools that are gated by policy
- Keeping program state in the typed heap

Shows how an existing library can run under Authority so its outbound requests
and tool calls are subject to policy, capabilities, and budgets.

## Simulation Mode

All notebooks use **simulation mode** by default (`simulate=True`). This means:

- No kernel binary required
- No external endpoints or credentials needed
- All operations run in-memory
- Convenient for learning and testing

To run against a real kernel, change `simulate=True` to `simulate=False`:

```python
# Simulation mode (default for tutorials)
with AuthorityKernel(simulate=True) as ak:
    ...

# Real kernel mode
with AuthorityKernel(simulate=False) as ak:
    ...
```

## Tips

1. **Run cells in order**: Each notebook is designed to be run top-to-bottom.

2. **Restart the kernel if stuck**: If something goes wrong, use Kernel > Restart.

3. **Check the SDK docs**: For more details, see the [documentation](https://authority-systems.github.io/nanos/).

4. **Experiment**: Modify the examples to explore different scenarios.

## Troubleshooting

### ImportError: No module named 'authority_nanos'

Install the SDK:
```bash
pip install authority-nanos
```

### Kernel not found

Make sure you are using a Python kernel that has the SDK installed.

### Simulation mode not working

Ensure you are passing `simulate=True` to `AuthorityKernel()`.

## Further Reading

- [Getting Started Guide](../docs/getting-started/)
- [API Reference](../docs/api/)
- [Security Documentation](../docs/security/)
- [Policy Configuration](../docs/policy/)
