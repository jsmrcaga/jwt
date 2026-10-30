(() => {
	// Closure to prevent pollution from other scripts
	// Magic 2001 features
	const select = document.createElement('select');
	select.setAttribute('aria-label', 'Documentation version');
	select.className = 'h-9 rounded-md bg-background px-2 text-sm text-muted-foreground';
	select.style.border = '1px solid var(--clean-border)';

	const current_version = document.querySelector('meta[name=docs_version]')?.getAttribute('value');
	const base_path = document.querySelector('meta[name=base_path]')?.getAttribute('value') || '';
	const base_url = new URL(window.location.href).origin;

	select.addEventListener('change', (event) => {
		console.log({event});
		const version = event.target.value;
		window.location.href = `${base_url}${base_path}/${version}`;
	});

	return fetch(`${base_url}${base_path}/versions.json`, {
		method: 'GET'
	}).then(res => {
		// No way to get versions :(
		if(!res.ok) {
			console.error('Could not get versions', res);
			return;
		}

		return res.json()
	}).then(({ versions }) => {

		const options = versions.forEach(version => {
			select.add(new Option(version, version, false, version === current_version));
		});

		const menubar_elements = document.querySelector('header .ml-auto');
		if(!menubar_elements) {
			console.log('Could not find menubar elements');
			return;
		}

		menubar_elements.prepend(select);
	}).catch(e => {
		console.error(e);
		return;
	});
})();
