<script>
	let message = "";

	function handleClick() {
		message = "Hello, World.";
	}
</script>

<main>
	<!-- Centered button -->
	<button on:click={handleClick}>
		<img src="/MetaMask-icon-fox.svg" alt="Fox Icon" class="fox-icon" />
		Connect MetaMask
	</button>

	<!-- If message is set, display it below the button -->
	{#if message}
		<p>{message}</p>
	{/if}
</main>

<style>
	/* Fill the entire screen to center the content */
	main {
		width: 100vw;
		height: 100vh;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		justify-content: center;
		align-items: center;
		font-family: sans-serif;
		background-color: #f5f5f5; /* Light gray background for a subtle style */
	}

	button {
		display: flex;
		align-items: center;
		background-color: #ffffff;
		border: 2px solid #ccc;
		border-radius: 8px;
		padding: 0.8rem 1.2rem;
		cursor: pointer;
		font-size: 1.1rem;
		box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
	}

	.fox-icon {
		width: 28px;
		height: 28px;
		margin-right: 0.5rem;
	}

	button:hover {
		background-color: #f0f0f0;
	}

	p {
		margin-top: 1rem;
		font-size: 1.2rem;
		color: #444;
	}
</style>
