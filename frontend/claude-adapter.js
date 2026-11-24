(function () {
  const listeners = [];

  async function apiFetch(url, options) {
    const resp = await fetch(url, options);
    if (resp.status === 401) {
      window.location.href = '/';
      throw new Error('Sessão expirada');
    }
    return resp;
  }

  async function notificarColecao(colecao) {
    for (const item of listeners) {
      if (item.colecao === colecao) {
        try {
          await item.atualizar();
        } catch (_) {}
      }
    }
  }

  try {
    const canal = new EventSource('/api/eventos');
    canal.onmessage = (evento) => {
      try {
        const dados = JSON.parse(evento.data);
        if (dados.colecao) notificarColecao(dados.colecao);
      } catch (_) {}
    };
  } catch (_) {}

  function separarCaminho(caminho) {
    const barra = caminho.indexOf('/');
    return {
      colecao: caminho.slice(0, barra),
      docId: caminho.slice(barra + 1),
    };
  }

  function criarDocRef(caminho) {
    const { colecao, docId } = separarCaminho(caminho);
    const url = `/api/db/${encodeURIComponent(colecao)}/${encodeURIComponent(docId)}`;

    const ler = async () => {
      const r = await apiFetch(url);
      const j = await r.json();
      return {
        exists: !!j.exists,
        id: docId,
        data: () => j.data,
      };
    };

    return {
      get: ler,
      async set(dados) {
        await apiFetch(url, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dados),
        });
        await notificarColecao(colecao);
      },
      async update(dados) {
        await apiFetch(url, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dados),
        });
        await notificarColecao(colecao);
      },
      async delete() {
        await apiFetch(url, { method: 'DELETE' });
        await notificarColecao(colecao);
      },
      onSnapshot(aoReceber) {
        const atualizar = async () => {
          const snap = await ler();
          aoReceber(snap);
        };
        listeners.push({ colecao, atualizar });
        atualizar();
        return () => {
          const i = listeners.findIndex((x) => x.atualizar === atualizar);
          if (i >= 0) listeners.splice(i, 1);
        };
      },
    };
  }

  function criarCollectionRef(nome, limite = null) {
    const lerLista = async () => {
      const query = limite ? `?limit=${limite}` : '';
      const r = await apiFetch(`/api/db/${encodeURIComponent(nome)}${query}`);
      const j = await r.json();
      const lista = j.docs || [];
      return {
        docs: lista.map((item, idx) =>
          nome === 'historico'
            ? { id: String(idx), data: () => item }
            : { id: item.id, data: () => item.data }
        ),
      };
    };

    return {
      get: lerLista,
      orderBy() {
        return criarCollectionRef(nome, limite);
      },
      limit(n) {
        return criarCollectionRef(nome, n);
      },
      async add(dados) {
        await apiFetch(`/api/db/${encodeURIComponent(nome)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dados),
        });
      },
      onSnapshot(aoReceber) {
        const atualizar = async () => {
          const snap = await lerLista();
          aoReceber(snap);
        };
        listeners.push({ colecao: nome, atualizar });
        atualizar();
        return () => {
          const i = listeners.findIndex((x) => x.atualizar === atualizar);
          if (i >= 0) listeners.splice(i, 1);
        };
      },
    };
  }

  const dbService = {
    doc: (caminho) => criarDocRef(caminho),
    collection: (nome) => criarCollectionRef(nome),
  };

  const assetsService = {
    async upload(blob) {
      const form = new FormData();
      form.append('file', blob, 'foto.jpg');
      const r = await apiFetch('/api/assets', { method: 'POST', body: form });
      if (!r.ok) throw new Error('Erro ao enviar foto');
      return await r.json();
    },
    async delete(assetId) {
      await apiFetch(`/api/assets/${encodeURIComponent(assetId)}`, { method: 'DELETE' });
    },
    async list() {
      const r = await apiFetch('/api/assets/usage');
      return await r.json();
    },
  };

  let cacheUsuario = null;
  async function obterUsuario() {
    if (!cacheUsuario) {
      const r = await apiFetch('/api/me');
      cacheUsuario = await r.json();
    }
    return cacheUsuario;
  }

  const userService = {
    async id() {
      return (await obterUsuario()).uid;
    },
    async isOwner() {
      return !!(await obterUsuario()).isOwner;
    },
    async can(permissao) {
      const u = await obterUsuario();
      if (permissao === 'data.write') return !!u.canWrite;
      return true;
    },
    async profiles(ids) {
      const r = await apiFetch('/api/users/profiles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      return await r.json();
    },
  };

  const downloadsService = {
    async save({ filename, data }) {
      const blob = data instanceof Blob ? data : new Blob([data]);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename || 'arquivo';
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { status: 'saved' };
    },
  };

  window.claude = {
    async use(servico) {
      if (servico === 'db') return dbService;
      if (servico === 'assets') return assetsService;
      if (servico === 'user') return userService;
      if (servico === 'downloads') return downloadsService;
      return null;
    },
  };

  // Cria a barra discreta de usuário logado / Usuários / Sair no canto inferior direito
  window.addEventListener('DOMContentLoaded', async () => {
    try {
      const u = await obterUsuario();
      const barra = document.createElement('div');
      barra.style.cssText = [
        'position:fixed',
        'bottom:14px',
        'right:14px',
        'z-index:9999',
        'display:flex',
        'align-items:center',
        'gap:8px',
        'padding:7px 12px',
        'border-radius:999px',
        'background:rgba(255,255,255,0.88)',
        'backdrop-filter:blur(10px)',
        'border:1px solid #D7DEE7',
        'box-shadow:0 6px 20px rgba(11,42,102,0.12)',
        'font-family:sans-serif',
        'font-size:12px',
        'color:#14202E'
      ].join(';');

      const nomeSpan = document.createElement('span');
      nomeSpan.style.fontWeight = '600';
      nomeSpan.textContent = u.nome;
      barra.appendChild(nomeSpan);

      if (u.isOwner) {
        const linkUsers = document.createElement('a');
        linkUsers.href = '/usuarios.html';
        linkUsers.textContent = 'Usuários';
        linkUsers.style.cssText = 'color:#034991;font-weight:700;text-decoration:none;padding:2px 6px;border-radius:6px;background:#E6EEF7;';
        barra.appendChild(linkUsers);
      }

      const btnSair = document.createElement('button');
      btnSair.type = 'button';
      btnSair.textContent = 'Sair';
      btnSair.style.cssText = 'border:none;background:#FEF2F2;color:#B91C1C;font-weight:700;padding:3px 8px;border-radius:6px;cursor:pointer;font-size:12px;';
      btnSair.addEventListener('click', async () => {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/';
      });
      barra.appendChild(btnSair);

      document.body.appendChild(barra);
    } catch (_) {}
  });
})();