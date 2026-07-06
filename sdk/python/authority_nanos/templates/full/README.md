# {{PROJECT_NAME}}

A full-featured starter program that runs under Authority, using the Authority SDK.

## Features

- Structured state management with dataclasses
- Task tracking and execution
- Configuration management
- Comprehensive security policy
- Logging and audit support
- Unit tests included

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run in simulation mode:
   ```bash
   python agent.py
   ```

3. Run in interactive mode:
   ```bash
   python agent.py --interactive
   ```

4. Run under the Authority kernel:
   ```bash
   authority run agent.py --policy policy.json
   ```

5. Run tests:
   ```bash
   pytest tests/
   ```

## Project Structure

```
{{PROJECT_NAME}}/
|-- agent.py          # Main program implementation
|-- policy.json       # Security policy
|-- config.json       # Runtime configuration
|-- requirements.txt  # Python dependencies
|-- tests/
|   |-- test_agent.py # Unit tests
|-- .gitignore        # Git ignore rules
```

## Configuration

Edit `config.json` to customize the program's behavior:

```json
{
  "agent_name": "{{PROJECT_NAME}}",
  "log_level": "INFO",
  "max_tasks": 100,
  "features": {
    "auto_cleanup": true,
    "verbose_logging": false
  }
}
```

## Security Policy

The policy (`policy.json`) enables:
- Heap operations with up to 100MB storage
- Network access for capability-gated outbound requests
- Filesystem access to config, data, and log directories
- Environment variable access for credentials
- Audit logging for all operations

## Architecture

### StateManager
Manages program state and tasks using the Authority kernel's typed heap.

```python
state_manager = StateManager(kernel)
state_manager.update_state(status="running")
state_manager.create_task("task_1", "Process data")
```

### ConfigManager
Loads and provides access to configuration from `config.json`.

```python
config = ConfigManager()
log_level = config.get("log_level", "INFO")
auto_cleanup = config.get("features.auto_cleanup", True)
```

### Agent
The main class that orchestrates state and task execution.

```python
agent = Agent(config, state_manager)
agent.start()
agent.execute_task("My task")
agent.stop()
```

## Extending the Program

### Adding New Task Types

```python
def execute_custom_task(self, data: dict) -> str:
    task_id = self.state.create_task(...)
    # Custom logic here
    self.state.complete_task(task_id, result)
    return result
```

### Adding Outbound Requests

The policy allows network access for outbound requests. Issue them through the
kernel so they are gated by policy and capabilities and charged against the
budget:

```python
response = kernel.inference(prompt="your payload", max_tokens=100)
```

## Learn More

- [Authority Documentation](https://mbhatt1.github.io/authority)
- [Policy Format Reference](https://mbhatt1.github.io/authority/policy/)
- [API Reference](https://mbhatt1.github.io/authority/api/)
- [Security Best Practices](https://mbhatt1.github.io/authority/security/)
